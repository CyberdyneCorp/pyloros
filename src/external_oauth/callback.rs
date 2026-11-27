use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    token_http::{client_ip, header},
};
use axum::{extract::ConnectInfo, http::HeaderMap};
use chrono::Utc;
use serde_json::Value;
use std::net::SocketAddr;
use uuid::Uuid;

type Internal = Box<dyn Error + Send + Sync>;
enum Failure {
    Provider(String),
    Unknown,
    State(state::InvalidState),
    Redirect,
    Exchange,
    Inactive(Uuid),
    Conflict(String),
}

impl Failure {
    fn reason(&self) -> &'static str {
        match self {
            Self::Provider(_) | Self::Exchange => "provider_error",
            Self::Unknown | Self::Redirect => "invalid_request",
            Self::State(_) => "invalid_state",
            Self::Inactive(_) => "inactive",
            Self::Conflict(_) => "email_unverified",
        }
    }
    fn response(&self) -> Response {
        let (status, title) = match self {
            Self::Provider(message) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    &format!("OAuth provider error: {message}"),
                );
            }
            Self::Unknown => (StatusCode::BAD_REQUEST, "Unknown OAuth provider"),
            Self::State(_) => (StatusCode::BAD_REQUEST, "Invalid or expired state"),
            Self::Redirect => (StatusCode::BAD_REQUEST, "frontend_redirect not permitted"),
            Self::Exchange => (StatusCode::BAD_REQUEST, "OAuth exchange failed"),
            Self::Inactive(_) => (StatusCode::FORBIDDEN, "User is inactive"),
            Self::Conflict(_) => (
                StatusCode::CONFLICT,
                "An account with this email already exists and the provider did not verify the email. Sign in with your existing method.",
            ),
        };
        problem(status, title)
    }
}

struct Input {
    code: String,
    state: String,
    error: Option<String>,
}
impl Input {
    fn parse(raw: Option<String>) -> Result<Self, Vec<Value>> {
        let mut query: HashMap<String, String> =
            url::form_urlencoded::parse(raw.as_deref().unwrap_or_default().as_bytes())
                .into_owned()
                .collect();
        let issues: Vec<_> = ["code", "state"]
            .into_iter()
            .filter(|k| !query.contains_key(*k))
            .map(
                |k| json!({"type":"missing","loc":["query",k],"msg":"Field required","input":null}),
            )
            .collect();
        if !issues.is_empty() {
            return Err(issues);
        }
        Ok(Self {
            code: query.remove("code").unwrap(),
            state: query.remove("state").unwrap(),
            error: query.remove("error").filter(|v| !v.is_empty()),
        })
    }
}

struct RequestInfo<'a> {
    provider: &'a str,
    origin: SessionOrigin<'a>,
    request: Option<&'a str>,
}
impl RequestInfo<'_> {
    async fn refusal(&self, pool: &PgPool, failure: Failure) -> Response {
        let mut details = json!({"provider":self.provider.chars().take(200).collect::<String>()});
        let mut subject = AuditSubject {
            user: None,
            email: None,
            organization: None,
        };
        match &failure {
            Failure::Provider(e) => {
                details["error"] = json!(e.chars().take(200).collect::<String>())
            }
            Failure::State(e) => details["detail"] = json!(e.to_string()),
            Failure::Conflict(email) => subject.email = Some(email.clone()),
            Failure::Inactive(user) => {
                subject.user = Some(*user);
                if let Ok((email, organization)) =
                    sqlx::query_as("SELECT primary_email,organization_id FROM users WHERE id=$1")
                        .bind(user)
                        .fetch_one(pool)
                        .await
                {
                    subject.email = email;
                    subject.organization = organization;
                }
            }
            _ => (),
        }
        if details.to_string().len() > 2048 {
            details = json!({"truncated":true});
        }
        let event = AuditActivity::Federated {
            identity: None,
            reason: Some(failure.reason()),
            details,
        };
        if write_activity(pool, event, subject, self.origin, self.request, Utc::now())
            .await
            .is_err()
        {
            eprintln!("could not record external OAuth refusal");
        }
        failure.response()
    }
}

pub(super) async fn handle(
    State(service): State<Arc<Service>>,
    Path(name): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    if service.forbidden_stub {
        return internal();
    }
    let input = match Input::parse(raw) {
        Ok(input) => input,
        Err(issues) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":issues})),
            )
                .into_response();
        }
    };
    let info = RequestInfo {
        provider: &name,
        origin: SessionOrigin {
            user_agent: header(&headers, "user-agent"),
            ip: client_ip(&headers, peer.ip(), service.proxies),
        },
        request: header(&headers, "x-request-id"),
    };
    match service.callback(&info, input).await {
        Ok(Ok(response)) => response,
        Ok(Err(refusal)) => info.refusal(&service.pool, refusal).await,
        Err(_) => internal(),
    }
}

type Outcome = Result<Result<Response, Failure>, Internal>;

impl Service {
    fn permits_return(&self, pending: &state::Pending) -> bool {
        pending
            .instructions
            .frontend_redirect
            .as_deref()
            .is_none_or(|s| !s.contains("..") && self.allowed.borrow().contains(s))
    }
    async fn callback(&self, info: &RequestInfo<'_>, input: Input) -> Outcome {
        if let Some(error) = input.error {
            return Ok(Err(Failure::Provider(error)));
        }
        let Some(provider) = self.providers.get(info.provider) else {
            return Ok(Err(Failure::Unknown));
        };
        let pending = match state::Pending::inspect(&self.pool, &input.state, info.provider).await?
        {
            Ok(p) => p,
            Err(e) => return Ok(Err(Failure::State(e))),
        };
        if !self.permits_return(&pending) {
            return Ok(Err(Failure::Redirect));
        }
        let profile = match provider.exchange(&input.code).await {
            Ok(p) => p,
            Err(_) => return Ok(Err(Failure::Exchange)),
        };
        self.complete(info, &pending, &profile).await
    }
    async fn complete(
        &self,
        info: &RequestInfo<'_>,
        pending: &state::Pending,
        profile: &provider::Profile,
    ) -> Outcome {
        let Some(key) = &self.wallet_key else {
            return Ok(Ok(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Wallet encryption key unavailable",
            )));
        };
        let mut tx = self.pool.begin().await?;
        if !pending.claim(&mut tx).await? {
            return Ok(Err(Failure::State(state::InvalidState::Consumed)));
        }
        if !self.permits_return(pending) {
            return Ok(Err(Failure::Redirect));
        }
        let account = match account::resolve(&mut tx, profile, key, self.webhooks).await {
            Ok(account) => account,
            Err(account::AccountError::UnverifiedEmail(email)) => {
                return Ok(Err(Failure::Conflict(email)));
            }
            Err(account::AccountError::Inactive(id)) => return Ok(Err(Failure::Inactive(id))),
            Err(e) => return Err(e.into()),
        };
        let now = Utc::now();
        let (email, organization) =
            sqlx::query_as("SELECT primary_email,organization_id FROM users WHERE id=$1")
                .bind(account.user)
                .fetch_one(&mut *tx)
                .await?;
        let event = AuditActivity::Federated {
            identity: Some((profile.provider, &profile.subject)),
            reason: None,
            details: json!({"is_new_user":account.created,"return_mode":pending.instructions.return_mode}),
        };
        write_activity(
            &mut *tx,
            event,
            AuditSubject {
                user: Some(account.user),
                email,
                organization,
            },
            info.origin,
            info.request,
            now,
        )
        .await?;
        let response = match pending.instructions.return_mode.as_str() {
            "cli" if self.cli => crate::browser_http::redirect(
                cli_return::issue(&mut tx, pending, account.user, now).await?,
            ),
            "cli" => {
                return Ok(Ok(problem(
                    StatusCode::BAD_REQUEST,
                    "CLI login is disabled",
                )));
            }
            "cookie" | "fragment" => {
                let Some(login) = &self.login else {
                    return Ok(Ok(problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Login signing unavailable",
                    )));
                };
                login
                    .federated(
                        &mut tx,
                        &account,
                        &pending.instructions,
                        self.post_login.as_deref(),
                        now,
                    )
                    .await?
            }
            _ => return Err("unsupported stored OAuth return mode".into()),
        };
        tx.commit().await?;
        Ok(Ok(response))
    }
}
