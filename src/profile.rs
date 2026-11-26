//! User profile authentication and projection for the PostgreSQL IAM deployment.
use crate::{config, token_authorization};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use chrono::{DateTime, SecondsFormat, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use std::{env, error::Error, sync::Arc};
use uuid::Uuid;

struct Verifier {
    key: DecodingKey,
    validation: Validation,
}

impl Verifier {
    fn configured(production: bool) -> Result<Option<Self>, Box<dyn Error>> {
        let public = config::pem("JWT_PUBLIC_KEY_PATH", "JWT_PUBLIC_KEY")?;
        let alg = env::var("JWT_ALGORITHM").unwrap_or_else(|_| {
            if public.is_some() {
                "RS256".into()
            } else {
                "HS256".into()
            }
        });
        let (alg, key) = match alg.as_str() {
            "RS256" => {
                let Some(pem) = public else { return Ok(None) };
                (Algorithm::RS256, DecodingKey::from_rsa_pem(pem.as_bytes())?)
            }
            "HS256" => {
                let Ok(secret) = env::var("JWT_SECRET_KEY") else {
                    return Ok(None);
                };
                if secret.is_empty() || (production && secret.len() < 32) {
                    return Err("invalid JWT_SECRET_KEY for profile verification".into());
                }
                (
                    Algorithm::HS256,
                    DecodingKey::from_secret(secret.as_bytes()),
                )
            }
            _ => return Err("unsupported access-token algorithm".into()),
        };
        let issuer = env::var("OIDC_ISSUER")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|oidc| oidc.trim_end_matches('/').to_owned())
            .or_else(|| env::var("JWT_ISSUER").ok())
            .unwrap_or_else(|| "cyberdyne-auth".into());
        Ok(Some(Self::new(alg, key, &issuer)))
    }

    fn new(alg: Algorithm, key: DecodingKey, issuer: &str) -> Self {
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.leeway = 0;
        validation.validate_aud = false;
        validation.validate_nbf = true;
        Self { key, validation }
    }

    fn read(&self, raw: &str) -> Option<Identity> {
        let claims = decode::<Claims>(raw, &self.key, &self.validation)
            .ok()?
            .claims;
        if claims.kind != "access" || claims.client_id.is_some_and(|id| id.starts_with("dcr_")) {
            return None;
        }
        Some(Identity {
            user: claims.sub.parse().ok()?,
            jti: claims.jti.parse().ok()?,
            sid: match claims.sid {
                Some(s) => Some(s.parse().ok()?),
                None => None,
            },
            iat: claims.iat,
        })
    }
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    jti: String,
    sid: Option<String>,
    iat: Option<i64>,
    client_id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
}
struct Identity {
    user: Uuid,
    jti: Uuid,
    sid: Option<Uuid>,
    iat: Option<i64>,
}

async fn revoked(tx: &mut Transaction<'_, Postgres>, id: &Identity) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM users WHERE id=$1)
        OR EXISTS(SELECT 1 FROM users WHERE id=$1 AND $2 <= floor(extract(epoch FROM tokens_valid_after))::bigint)
        OR EXISTS(SELECT 1 FROM revoked_tokens WHERE jti=$3)
        OR EXISTS(SELECT 1 FROM sessions WHERE id=$4 AND revoked_at IS NOT NULL)")
        .bind(id.user).bind(id.iat).bind(id.jti).bind(id.sid).fetch_one(&mut **tx).await
}

struct Profile {
    pool: PgPool,
    verify: Option<Verifier>,
    enforce: bool,
    admins: Vec<String>,
    production: bool,
}

pub fn routes(pool: PgPool, production: bool) -> Result<Router, Box<dyn Error>> {
    let state = Profile {
        pool,
        verify: Verifier::configured(production)?,
        enforce: config::flag("ENFORCE_TOKEN_REVOCATION")?,
        admins: config::admin_emails()?,
        production,
    };
    Ok(Router::new()
        .route("/api/v1/users/me", any(current))
        .with_state(Arc::new(state)))
}

fn credential(headers: &HeaderMap) -> Option<&str> {
    if let Some((scheme, token)) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        && scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
    {
        return Some(token);
    }
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|entry| entry.trim().split_once('='))
        .filter(|(key, _)| *key == "access_token")
        .map(|(_, v)| v.trim_matches('"'))
        .next_back()
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED,[(header::WWW_AUTHENTICATE,"Bearer, Cookie name=\"access_token\"")],
        Json(json!({"type":"about:blank","status":401,"title":"Not authenticated","detail":"Not authenticated"}))).into_response()
}

async fn current(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW,"GET")],
            Json(json!({"type":"about:blank","title":"Method Not Allowed","detail":"Method Not Allowed","status":405}))).into_response();
    }
    let Some(id) = credential(&headers).and_then(|raw| state.verify.as_ref()?.read(raw)) else {
        return unauthorized();
    };
    match load(&state, &id).await {
        Ok(result) => result,
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
        )
            .into_response(),
    }
}

async fn load(state: &Profile, id: &Identity) -> Result<Response, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, id).await? {
        return Ok(unauthorized());
    }
    let row = sqlx::query_as::<_, (Value, DateTime<Utc>)>(include_str!("profile.sql"))
        .bind(id.user)
        .fetch_optional(&mut *tx)
        .await?;
    let Some((mut doc, created)) = row else {
        return Ok((StatusCode::NOT_FOUND,Json(json!({"type":"about:blank","status":404,"title":"User not found","detail":"User not found"}))).into_response());
    };
    let precision = if created.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    doc["created_at"] = json!(created.to_rfc3339_opts(precision, true));
    doc["is_admin"] = json!(config::effective_admin(
        doc["is_admin"] == true,
        doc["email"].as_str(),
        doc["is_email_verified"] == true,
        state.production,
        &state.admins
    ));
    let roles = token_authorization::profile_roles(&mut tx, id.user).await?;
    doc["roles"] = json!(roles.as_ref().map(|r| &r.global));
    doc["org_roles"] = json!(roles.as_ref().map(|r| &r.organizations));
    tx.commit().await?;
    Ok(Json(doc).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_trusted_user_access_credentials_identify_the_profile() {
        use jsonwebtoken::{EncodingKey, Header, encode};
        let secret = b"profile-test-only";
        let verifier = Verifier::new(Algorithm::HS256, DecodingKey::from_secret(secret), "issuer");
        let user = Uuid::new_v4();
        let base = json!({
            "sub":user.to_string(),"iss":"issuer","exp":Utc::now().timestamp()+300,
            "jti":Uuid::new_v4().to_string(),"type":"access","client_id":"registered",
            "aud":"https://resource.example"
        });
        let sign = |claims: &Value, key: &[u8]| {
            encode(&Header::default(), claims, &EncodingKey::from_secret(key)).unwrap()
        };
        assert_eq!(verifier.read(&sign(&base, secret)).unwrap().user, user);
        assert!(verifier.read(&sign(&base, b"unknown-test-key")).is_none());
        for (field, value) in [
            ("iss", json!("other")),
            ("exp", json!(1)),
            ("type", json!("refresh")),
            ("client_id", json!("dcr_test")),
        ] {
            let mut claims = base.clone();
            claims[field] = value;
            assert!(verifier.read(&sign(&claims, secret)).is_none());
        }
    }

    #[test]
    fn explicit_bearer_wins_and_other_schemes_use_the_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "csrf=example; access_token=cookie".parse().unwrap(),
        );
        headers.insert(header::AUTHORIZATION, "bEaReR explicit".parse().unwrap());
        assert_eq!(credential(&headers), Some("explicit"));
        headers.insert(header::AUTHORIZATION, "Basic unrelated".parse().unwrap());
        assert_eq!(credential(&headers), Some("cookie"));
    }
}
