//! Device authorization initiation. A device and browser may reach different issuers.
use super::{basic, client_ip, fields, header, internal};
use crate::{
    browser_prompt::quoted_list,
    client_auth,
    discovery::Provider,
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_throttle::LoginThrottle,
    token_runtime::number,
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{TimeDelta, Utc};
use rand::{Rng, RngCore, rngs::OsRng};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{collections::BTreeSet, error::Error, net::SocketAddr, sync::Arc};
use uuid::Uuid;

const PATH: &str = "/api/v1/auth/oauth2/device_authorization";
pub(super) const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub(super) const LETTERS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

struct Device {
    pool: PgPool,
    uri: String,
    lifetime: i64,
    interval: i32,
    quota: LoginThrottle,
    proxies: usize,
}

pub(super) fn routes(
    provider: Option<&Provider>,
    pool: PgPool,
    proxies: usize,
) -> Result<Router, Box<dyn Error>> {
    let Some(provider) = provider.filter(|p| p.device_authorization_enabled()) else {
        return Ok(Router::new().route(
            PATH,
            post(|| async { crate::login_http::problem(StatusCode::NOT_FOUND, "Not found") })
                .fallback(super::post_only),
        ));
    };
    let lifetime = number("OAUTH_DEVICE_CODE_TTL_SECONDS", 600)?;
    let interval = number("OAUTH_DEVICE_POLL_INTERVAL_SECONDS", 5)?;
    if !(60..=1800).contains(&lifetime) || !(1..=60).contains(&interval) {
        return Err("device code lifetime or polling interval out of range".into());
    }
    let config = Device {
        pool,
        uri: format!("{}/api/v1/auth/oauth2/device", provider.issuer()),
        lifetime,
        interval: interval.try_into()?,
        quota: LoginThrottle::new(number("RATELIMIT_DEVICE_AUTHORIZATION_PER_MIN", 10)?),
        proxies,
    };
    Ok(Router::new()
        .route(PATH, post(start).fallback(super::post_only))
        .with_state(Arc::new(config)))
}

struct Input<'a> {
    client: &'a str,
    secret: Option<&'a str>,
    scope: &'a str,
    resource: bool,
}

pub(super) struct Refusal(pub(super) &'static str, pub(super) String);

impl Refusal {
    fn response(&self) -> (StatusCode, Value) {
        let (status, code) = match self.0 {
            "invalid_client" => (StatusCode::UNAUTHORIZED, self.0),
            "rate_limited" => (StatusCode::TOO_MANY_REQUESTS, "invalid_request"),
            _ => (StatusCode::BAD_REQUEST, self.0),
        };
        (status, json!({"error":code,"error_description":self.1}))
    }
}

async fn start(
    State(state): State<Arc<Device>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let headers = req.headers().clone();
    let values = match fields(req).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let form = |name: &str| {
        values
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let (id, secret) = basic(&headers).unwrap_or_default();
    let input = Input {
        client: if id.is_empty() {
            form("client_id").unwrap_or_default()
        } else {
            &id
        },
        secret: if secret.is_empty() {
            form("client_secret")
        } else {
            Some(&secret)
        },
        scope: form("scope").unwrap_or_default(),
        resource: values.iter().any(|(k, _)| k == "resource"),
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: header(&headers, "user-agent"),
    };
    match state
        .issue(input, origin, header(&headers, "x-request-id"))
        .await
    {
        Ok((status, body)) => (
            status,
            [("cache-control", "no-store"), ("pragma", "no-cache")],
            Json(body),
        )
            .into_response(),
        Err(_) => internal(),
    }
}

pub(super) async fn authenticated_scopes(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
    secret: Option<&str>,
    quota: Option<(&LoginThrottle, Option<std::net::IpAddr>)>,
) -> Result<Result<String, Refusal>, sqlx::Error> {
    if client.is_empty() {
        return Ok(Err(Refusal("invalid_client", "missing client_id".into())));
    }
    let row = sqlx::query(
        "SELECT client_type,grant_types,allowed_scopes,registration_source,secret_hash,
            CASE WHEN previous_secret_expires_at > now() THEN previous_secret_hash END AS grace_hash
            FROM oauth_clients WHERE client_id=$1 AND active FOR SHARE",
    )
    .bind(client)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(Err(Refusal("invalid_client", "unknown client".into())));
    };
    if quota.is_some_and(|(limit, ip)| !limit.allow_client(Some(client), ip)) {
        return Ok(Err(Refusal(
            "rate_limited",
            "device authorization quota exceeded".into(),
        )));
    }
    if !client_auth::authenticates(&row, secret).await? {
        return Ok(Err(Refusal("invalid_client", "bad client secret".into())));
    }
    if row.try_get::<&str, _>("registration_source")? == "dynamic" {
        return Ok(Err(Refusal(
            "unauthorized_client",
            "dynamically registered clients may not use the device grant".into(),
        )));
    }
    if !row
        .try_get::<&str, _>("grant_types")?
        .split_whitespace()
        .any(|g| g == GRANT)
    {
        return Ok(Err(Refusal(
            "unauthorized_client",
            "client may not use the device_code grant".into(),
        )));
    }
    Ok(Ok(row.try_get("allowed_scopes")?))
}

impl Device {
    async fn authorize(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        input: &Input<'_>,
        ip: Option<std::net::IpAddr>,
    ) -> Result<Result<Vec<String>, Refusal>, sqlx::Error> {
        let allowed =
            match authenticated_scopes(tx, input.client, input.secret, Some((&self.quota, ip)))
                .await?
            {
                Ok(allowed) => allowed,
                Err(failure) => return Ok(Err(failure)),
            };
        if input.resource {
            return Ok(Err(Refusal(
                "invalid_target",
                "resource indicators are not supported for the device grant".into(),
            )));
        }
        Ok(scopes(input.scope, &allowed))
    }

    async fn issue(
        &self,
        input: Input<'_>,
        origin: SessionOrigin<'_>,
        request_id: Option<&str>,
    ) -> Result<(StatusCode, Value), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();
        let subject = AuditSubject {
            user: None,
            email: None,
            organization: None,
        };
        let scopes = match self.authorize(&mut tx, &input, origin.ip).await? {
            Ok(scopes) => scopes,
            Err(failure) => {
                tx.rollback().await?;
                if write_activity(
                    &self.pool,
                    AuditActivity::DeviceStart(input.client, Some(failure.0), json!({})),
                    subject,
                    origin,
                    request_id,
                    now,
                )
                .await
                .is_err()
                {
                    eprintln!("could not record device authorization refusal");
                }
                return Ok(failure.response());
            }
        };
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        let token = URL_SAFE_NO_PAD.encode(random);
        let digest = crate::authorization_codes::digest(&token);
        let expires = now + TimeDelta::seconds(self.lifetime);
        for _ in 0..5 {
            let code: String = (0..8)
                .map(|_| LETTERS[OsRng.gen_range(0..LETTERS.len())] as char)
                .collect();
            let inserted = sqlx::query(
                "INSERT INTO device_authorizations
                    (id, device_code_hash, user_code, client_id, scopes, status,
                     interval_seconds, created_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8)
                 ON CONFLICT (user_code) DO NOTHING",
            )
            .bind(Uuid::new_v4())
            .bind(&digest)
            .bind(&code)
            .bind(input.client)
            .bind(scopes.join(" "))
            .bind(self.interval)
            .bind(now)
            .bind(expires)
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 0 {
                continue;
            }
            let shown = format!("{}-{}", &code[..4], &code[4..]);
            let bounded: Vec<String> = scopes
                .iter()
                .map(|s| s.chars().take(200).collect())
                .collect();
            let mut details = json!({"scope":bounded,"expires_in":self.lifetime});
            if details.to_string().len() > 2048 {
                details = json!({"truncated":true});
            }
            write_activity(
                &mut *tx,
                AuditActivity::DeviceStart(input.client, None, details),
                subject,
                origin,
                request_id,
                now,
            )
            .await?;
            tx.commit().await?;
            return Ok((
                StatusCode::OK,
                json!({"device_code":token,"user_code":shown,"verification_uri":self.uri,
                "verification_uri_complete":format!("{}?user_code={shown}",self.uri),"expires_in":self.lifetime,"interval":self.interval}),
            ));
        }
        tx.rollback().await?;
        let failure = Refusal("invalid_request", "could not allocate a user code".into());
        let _ = write_activity(
            &self.pool,
            AuditActivity::DeviceStart(input.client, Some(failure.0), json!({})),
            subject,
            origin,
            request_id,
            now,
        )
        .await;
        Ok(failure.response())
    }
}

fn scopes(raw: &str, allowed: &str) -> Result<Vec<String>, Refusal> {
    let requested: BTreeSet<_> = raw.split_whitespace().collect();
    if requested.is_empty() {
        return Err(Refusal("invalid_scope", "scope is required".into()));
    }
    let allowed: BTreeSet<_> = allowed.split_whitespace().collect();
    let extra: Vec<_> = requested.difference(&allowed).copied().collect();
    if !extra.is_empty() {
        return Err(Refusal(
            "invalid_scope",
            format!(
                "scopes not allowed for this client: {}",
                quoted_list(&extra)
            ),
        ));
    }
    Ok(requested.into_iter().map(str::to_owned).collect())
}

#[cfg(test)]
mod tests;
