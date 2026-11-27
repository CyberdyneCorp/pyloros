//! Browser verification uses the same deployment-supplied pages as the original issuer.
mod decision;
use super::{client_ip, header};
use crate::{
    browser_http, browser_prompt, consent_page,
    discovery::Provider,
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    login_throttle::LoginThrottle,
    token_runtime::{Runtime, number},
};
use axum::{
    Router,
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::get,
};
use chrono::Utc;
use minijinja::{Environment, context};
use serde::Deserialize;
use sqlx::{Postgres, Row, Transaction};
use std::{collections::BTreeMap, env, error::Error, fs, net::SocketAddr, sync::Arc};
use uuid::Uuid;

const PATH: &str = "/api/v1/auth/oauth2/device";
const DECISION: &str = "/api/v1/auth/oauth2/device/decision";
type PageError = Box<dyn Error + Send + Sync>;
type PageResult = Result<Response, PageError>;

#[derive(Deserialize)]
struct Bundle {
    pages: BTreeMap<String, String>,
    descriptions: BTreeMap<String, String>,
}
struct Browser {
    runtime: Option<Arc<Runtime>>,
    templates: Option<Environment<'static>>,
    descriptions: BTreeMap<String, String>,
    catalog: tokio::sync::watch::Receiver<BTreeMap<String, String>>,
    quota: LoginThrottle,
    proxies: usize,
}

pub(super) fn routes(
    provider: Option<&Provider>,
    runtime: Option<Arc<Runtime>>,
    proxies: usize,
) -> Result<Router, Box<dyn Error>> {
    let Some(provider) = provider.filter(|p| p.device_authorization_enabled()) else {
        return Ok(Router::new()
            .route(
                DECISION,
                axum::routing::post(|| async { problem(StatusCode::NOT_FOUND, "Not found") })
                    .fallback(super::post_only),
            )
            .route(
                PATH,
                get(|| async { problem(StatusCode::NOT_FOUND, "Not found") })
                    .head(browser_http::method_not_allowed)
                    .fallback(browser_http::method_not_allowed),
            ));
    };
    let mut templates = None;
    let mut descriptions = BTreeMap::new();
    if let Some(path) = env::var_os("PYLOROS_DEVICE_UI_PATH") {
        let bundle: Bundle = serde_json::from_slice(&fs::read(path)?)?;
        let mut pages = consent_page::html_environment();
        for (name, source) in bundle.pages {
            pages.add_template_owned(name, source)?;
        }
        for name in [
            "entry",
            "entry_error",
            "confirm",
            "confirm_trusted",
            "approved",
            "denied",
            "error",
        ] {
            pages.get_template(name)?;
        }
        templates = Some(pages);
        descriptions = bundle.descriptions;
    }
    let state = Browser {
        runtime,
        catalog: provider.scope_catalog(),
        templates,
        descriptions,
        quota: LoginThrottle::new(number("RATELIMIT_DEVICE_VERIFY_PER_MIN", 10)?),
        proxies,
    };
    Ok(Router::new()
        .route(
            PATH,
            get(verify)
                .head(browser_http::method_not_allowed)
                .fallback(browser_http::method_not_allowed),
        )
        .route(
            DECISION,
            axum::routing::post(decision::submit).fallback(super::post_only),
        )
        .with_state(Arc::new(state)))
}

fn unavailable() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Device verification unavailable",
    )
}

async fn verify(
    State(browser): State<Arc<Browser>>,
    OriginalUri(uri): OriginalUri,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(rt) = &browser.runtime else {
        return unavailable();
    };
    browser
        .verify(rt, &uri, &headers, peer)
        .await
        .unwrap_or_else(|_| unavailable())
}

impl Browser {
    fn render(&self, name: &str, status: StatusCode, values: minijinja::Value) -> PageResult {
        let Some(templates) = &self.templates else {
            return Ok(unavailable());
        };
        let html = templates.get_template(name)?.render(values)?;
        Ok(consent_page::html_response(status, html))
    }

    async fn verify(
        &self,
        rt: &Runtime,
        uri: &Uri,
        headers: &HeaderMap,
        peer: SocketAddr,
    ) -> PageResult {
        let mut tx = rt.pool.begin().await?;
        let Some(session) = rt
            .verifier
            .browser_session(headers, &mut tx, rt.enforce_revocation)
            .await?
        else {
            let Some(login) = &rt.login_url else {
                return Ok(problem(
                    StatusCode::UNAUTHORIZED,
                    "Authentication required and no login URL is configured",
                ));
            };
            let issuer = url::Url::parse(rt.signer.issuer())?;
            let origin = header(headers, "host")
                .map(|host| format!("{}://{host}", issuer.scheme()))
                .unwrap_or_else(|| issuer.origin().ascii_serialization());
            let target = format!(
                "{origin}{}",
                uri.path_and_query().map_or(PATH, |p| p.as_str())
            );
            return Ok(browser_http::redirect(browser_prompt::login_location(
                login,
                &target,
                false,
                Utc::now(),
            )));
        };
        let raw = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
            .filter(|(key, _)| key == "user_code")
            .last()
            .map(|(_, v)| v);
        let Some(raw) = raw.filter(|v| !v.is_empty()) else {
            return self.render("entry", StatusCode::OK, context! {action=>PATH});
        };
        let origin = SessionOrigin {
            ip: client_ip(headers, peer.ip(), self.proxies),
            user_agent: header(headers, "user-agent"),
        };
        let by_user = self
            .quota
            .allow_client(Some(&session.user.to_string()), None);
        let by_ip = self.quota.allow(origin.ip);
        let lookup = if by_user && by_ip {
            lookup(&mut tx, &raw).await?
        } else {
            Err(("rate_limited", None))
        };
        let row = match lookup {
            Ok(row) => row,
            Err((reason, client)) => {
                tx.rollback().await?;
                let subject = AuditSubject {
                    user: Some(session.user),
                    email: None,
                    organization: None,
                };
                if write_activity(
                    &rt.pool,
                    AuditActivity::DeviceLookup(client.as_deref().unwrap_or_default(), reason),
                    subject,
                    origin,
                    header(headers, "x-request-id"),
                    Utc::now(),
                )
                .await
                .is_err()
                {
                    eprintln!("could not record device lookup refusal");
                }
                let (status, message) = if reason == "rate_limited" {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        "Too many attempts. Wait a minute and try again.",
                    )
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        "That code is not valid or has expired. Check the code on your device.",
                    )
                };
                return self.render(
                    "entry_error",
                    status,
                    context! {action=>PATH,error=>message},
                );
            }
        };
        let client: &str = row.try_get("client_id")?;
        let id: Uuid = row.try_get("id")?;
        let code: &str = row.try_get("user_code")?;
        let mut ordered = row
            .try_get::<&str, _>("scopes")?
            .split_whitespace()
            .collect::<Vec<_>>();
        ordered.sort_unstable();
        ordered.dedup();
        let names = ordered.join(" ");
        let scopes = {
            let catalog = self.catalog.borrow();
            ordered.iter().map(|name|context!{name=>*name, description=>self.descriptions.get(*name).or_else(||catalog.get(*name)).map_or("",String::as_str)}).collect::<Vec<_>>()
        };
        let ticket = consent_page::sign_ticket(
            &rt.signer,
            session.user,
            client,
            "",
            &names,
            &format!("device_authorization={id}"),
            Utc::now(),
        )?;
        let template = if row.try_get("trusted")? {
            "confirm_trusted"
        } else {
            "confirm"
        };
        self.render(template, StatusCode::OK, context!{
            action => DECISION, client_id => client, client_name => row.try_get::<&str,_>("name")?,
            scopes, ticket, user_code => format!("{}-{}", &code[..4], &code[4..]),
        })
    }
}

async fn lookup(
    tx: &mut Transaction<'_, Postgres>,
    raw: &str,
) -> Result<Result<sqlx::postgres::PgRow, (&'static str, Option<String>)>, sqlx::Error> {
    let normalized: String = raw
        .to_uppercase()
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .collect();
    if raw.chars().count() > 32
        || normalized.len() != 8
        || !normalized
            .bytes()
            .all(|c| super::device::LETTERS.contains(&c))
    {
        return Ok(Err(("invalid_token", None)));
    }
    let row = sqlx::query(
        "SELECT d.id, d.user_code, d.client_id, d.status, d.scopes, d.expires_at<=now() AS expired,
                c.name, c.trusted, coalesce(c.active AND c.registration_source<>'dynamic' AND
                $2=ANY(regexp_split_to_array(c.grant_types,'[[:space:]]+')),false) AS eligible
         FROM device_authorizations d LEFT JOIN oauth_clients c ON c.client_id=d.client_id
         WHERE d.user_code=$1",
    )
    .bind(normalized)
    .bind(super::device::GRANT)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(Err(("invalid_token", None)));
    };
    let reason = if row.try_get("expired")? {
        Some("expired")
    } else if row.try_get::<&str, _>("status")? != "pending" {
        Some("invalid_token")
    } else if !row.try_get::<bool, _>("eligible")? {
        Some("unauthorized_client")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Ok(Err((reason, Some(row.try_get("client_id")?))));
    }
    Ok(Ok(row))
}
