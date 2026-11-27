//! Clear browser credentials and revoke the presented tokens.
use super::*;
use crate::csrf::{bearer, cookie};

pub(super) async fn handle(
    State(login): State<Option<Arc<Login>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != axum::http::Method::POST {
        let mut res = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        res.headers_mut().insert(h::ALLOW, "POST".parse().unwrap());
        return res;
    }
    let Some(login) = login else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Login signing unavailable");
    };
    let (parts, body) = req.into_parts();
    let refresh = match refresh::read_token(&parts.headers, body).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let access = bearer(&parts.headers).or_else(|| cookie(&parts.headers, "access_token"));
    let origin = SessionOrigin {
        ip: client_ip(&parts.headers, peer.ip(), login.proxies),
        user_agent: header(&parts.headers, "user-agent"),
    };
    let request = header(&parts.headers, "x-request-id");
    login
        .logout(access, refresh.as_deref(), origin, request)
        .await
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
            )
                .into_response()
        })
}

impl Login {
    async fn logout(
        &self,
        access: Option<&str>,
        refresh: Option<&str>,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> LoginResult {
        let now = Utc::now();
        let access = access.and_then(|token| self.verifier.revocable_access(token));
        let identity = refresh.map(|token| self.verifier.refresh(token));
        if access.is_some() || matches!(identity, Some(Ok(_))) {
            let mut tx = self.pool.begin().await?;
            if let Some(token) = &access {
                sqlx::query(
                    "INSERT INTO revoked_tokens(jti,expires_at,revoked_at,client_id,reason)
                         VALUES ($1,$2,$3,$4,'logout') ON CONFLICT(jti) DO NOTHING",
                )
                .bind(token.jti)
                .bind(token.expires)
                .bind(now)
                .bind(&token.client)
                .execute(&mut *tx)
                .await?;
            }
            if let Some(Ok(id)) = &identity {
                refresh::revoke_family(&mut tx, *id).await?;
                let mut details = json!({"session_id":id.session});
                if access.is_some() {
                    details["access_token_revoked"] = json!(true);
                }
                write_activity(
                    &mut *tx,
                    AuditActivity::Logoff {
                        reason: None,
                        details,
                    },
                    AuditSubject {
                        user: Some(id.user),
                        email: None,
                        organization: None,
                    },
                    origin,
                    request,
                    now,
                )
                .await?;
            }
            tx.commit().await?;
        }
        if let Some(Err(error)) = identity {
            let reason = error.audit_reason();
            if write_activity(
                &self.pool,
                AuditActivity::Logoff {
                    reason: Some(reason),
                    details: json!({}),
                },
                AuditSubject {
                    user: None,
                    email: None,
                    organization: None,
                },
                origin,
                request,
                now,
            )
            .await
            .is_err()
            {
                eprintln!("could not record invalid logout credential");
            }
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        self.cookies.clear(response.headers_mut(), now);
        Ok(response)
    }
}
