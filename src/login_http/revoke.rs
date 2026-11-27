//! OAuth client-authenticated revocation.
use super::*;
use crate::{
    client_auth, token_http,
    token_revocation::{self, Outcome, TokenError, VerifiedToken},
};
use axum::http::{HeaderValue, Method};
use serde_json::Value;

struct Decision {
    response: Response,
    reason: Option<&'static str>,
    user: Option<Uuid>,
    details: Value,
    audit: bool,
}
impl Decision {
    fn empty(reason: Option<&'static str>) -> Self {
        Self {
            response: StatusCode::OK.into_response(),
            reason,
            user: None,
            details: json!({}),
            audit: true,
        }
    }
    fn error(status: StatusCode, code: &str, message: &str, reason: &'static str) -> Self {
        Self {
            response: (
                status,
                Json(json!({"error":code,"error_description":message})),
            )
                .into_response(),
            ..Self::empty(Some(reason))
        }
    }
    fn for_token(token: &VerifiedToken, outcome: Outcome) -> Self {
        if outcome == Outcome::Unknown {
            return Self::empty(Some("invalid_token"));
        }
        let mut decision =
            Self::empty((outcome == Outcome::DifferentOwner).then_some("client_mismatch"));
        let (user, kind) = match token {
            VerifiedToken::Access { user, .. } => (Some(*user), "access_token"),
            VerifiedToken::Service { .. } => (None, "service_token"),
            VerifiedToken::Refresh { user, session, .. } => {
                if outcome == Outcome::Revoked {
                    decision.details["session_id"] = json!(session);
                }
                (Some(*user), "refresh_token")
            }
        };
        decision.user = user;
        decision.details["token_type"] = json!(kind);
        decision
    }
}

pub(super) async fn handle(
    State(login): State<Option<Arc<Login>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    base: crate::foundation::RequestOrigin,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(h::ALLOW, HeaderValue::from_static("POST"));
        return r;
    }
    let headers = req.headers().clone();
    let fields = match token_http::fields(req).await {
        Ok(f) => f,
        Err(r) => return *r,
    };
    let field = |key: &str| {
        fields
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|s| !s.is_empty())
    };
    let Some(token) = field("token") else {
        return no_store(
            Decision::error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing token parameter",
                "invalid_request",
            )
            .response,
        );
    };
    let Some(login) = login else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Login signing unavailable");
    };
    let (id, secret) = token_http::basic(&headers).unwrap_or_default();
    let client = if id.is_empty() {
        field("client_id").unwrap_or_default()
    } else {
        &id
    };
    let secret = if secret.is_empty() {
        field("client_secret")
    } else {
        Some(secret.as_str())
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), login.proxies),
        user_agent: header(&headers, "user-agent"),
    };
    match login
        .revoke_client_token(
            client,
            secret,
            token,
            origin,
            header(&headers, "x-request-id"),
            login.oidc_issuer.as_deref().or(base.0.as_deref()),
        )
        .await
    {
        Ok(r) => no_store(r),
        Err(_) => crate::headers::unhandled_error(),
    }
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(h::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.headers_mut()
        .insert(h::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

impl Login {
    async fn revoke_client_token(
        &self,
        client: &str,
        secret: Option<&str>,
        token: &str,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
        oidc_issuer: Option<&str>,
    ) -> LoginResult {
        let mut tx = self.pool.begin().await?;
        let decision = self
            .revocation_decision(&mut tx, client, secret, token, origin.ip, oidc_issuer)
            .await?;
        let event = AuditActivity::Revoke {
            client,
            reason: decision.reason,
            details: decision.details,
        };
        let subject = AuditSubject {
            user: decision.user,
            email: None,
            organization: None,
        };
        if decision.reason.is_none() {
            write_activity(&mut *tx, event, subject, origin, request, Utc::now()).await?;
            tx.commit().await?;
        } else {
            tx.rollback().await?;
            if decision.audit
                && write_activity(&self.pool, event, subject, origin, request, Utc::now())
                    .await
                    .is_err()
            {
                eprintln!("could not record token revocation refusal");
            }
        }
        Ok(decision.response)
    }
    async fn revocation_decision(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        client: &str,
        secret: Option<&str>,
        token: &str,
        ip: Option<std::net::IpAddr>,
        oidc_issuer: Option<&str>,
    ) -> Result<Decision, sqlx::Error> {
        let now = Utc::now();
        let record = client_auth::registration(tx, client, now).await?;
        if !self
            .revoke_quota
            .allow_client(record.as_ref().map(|_| client), ip)
        {
            let msg = if record.is_some() {
                "revocation quota exceeded for this client"
            } else {
                "revocation quota exceeded for this address"
            };
            let mut decision = Decision::error(
                StatusCode::TOO_MANY_REQUESTS,
                "invalid_request",
                msg,
                "rate_limited",
            );
            decision.audit = record.is_some();
            return Ok(decision);
        }
        let Some(record) = record else {
            let msg = if client.is_empty() {
                "missing client_id"
            } else {
                "unknown client"
            };
            return Ok(Decision::error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                msg,
                "invalid_client",
            ));
        };
        if !client_auth::authenticates(&record, secret).await? {
            return Ok(Decision::error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "bad client secret",
                "invalid_client",
            ));
        }
        Ok(
            match self.verifier.token_for_revocation_at(token, oidc_issuer) {
                Ok(credential) => Decision::for_token(
                    &credential,
                    token_revocation::revoke(tx, client, &credential, now).await?,
                ),
                Err(TokenError::Unsupported) => Decision::error(
                    StatusCode::BAD_REQUEST,
                    "unsupported_token_type",
                    "only access and refresh tokens can be revoked",
                    "unsupported_token_type",
                ),
                Err(TokenError::Expired) => Decision::empty(Some("expired")),
                Err(TokenError::Invalid) => Decision::empty(Some("invalid_token")),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_token_returns_an_uncacheable_oauth_error_before_authentication() {
        let peer = "127.0.0.1:3000".parse().unwrap();
        let request = Request::post("/api/v1/auth/oauth2/revoke")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = handle(
            State(None),
            ConnectInfo(peer),
            crate::foundation::RequestOrigin(None),
            request,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[h::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[h::PRAGMA], "no-cache");
        let bytes = axum::body::to_bytes(response.into_body(), 512)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"error":"invalid_request","error_description":"missing token parameter"})
        );
    }

    #[test]
    fn unidentified_clients_share_only_the_address_budget() {
        let limit = LoginThrottle::new(1);
        let ip = Some("192.0.2.1".parse().unwrap());
        assert!(limit.allow_client(None, ip));
        assert!(!limit.allow_client(None, ip));
        assert!(limit.allow_client(Some("registered"), ip));
        assert!(!limit.allow_client(Some("registered"), ip));
        assert!(limit.allow_client(Some("second"), ip));
        assert!(limit.allow_client(Some("registered"), Some("192.0.2.2".parse().unwrap())));
    }
}
