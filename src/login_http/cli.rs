//! Redeem the code delivered to the CLI's loopback listener.
use super::*;
use crate::{
    authorization_codes::digest, code_exchange::matches_s256, login_throttle::RateLimited,
};
use chrono::DateTime;
use sqlx::Row;

pub(super) async fn handle(
    State(login): State<Option<Arc<Login>>>,
    axum::Extension(enabled): axum::Extension<bool>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != axum::http::Method::POST {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(h::ALLOW, "POST".parse().unwrap());
        return response;
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 2 * 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let Ok(body) = crate::request_json::parse_body(&parts.headers, &bytes) else {
        return invalid_grant();
    };
    let Some((code, verifier)) = fields(&body) else {
        return invalid_grant();
    };
    if !enabled {
        return problem(StatusCode::BAD_REQUEST, "CLI login is disabled");
    }
    let Some(login) = login else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Login signing unavailable");
    };
    let origin = SessionOrigin {
        ip: client_ip(&parts.headers, peer.ip(), login.proxies),
        user_agent: header(&parts.headers, "user-agent"),
    };
    if !login.cli_quota.allow(origin.ip) {
        return RateLimited.into_response();
    }
    login
        .exchange_cli(
            code,
            verifier,
            origin,
            header(&parts.headers, "x-request-id"),
        )
        .await
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
            )
                .into_response()
        })
}

fn fields(body: &serde_json::Value) -> Option<(&str, &str)> {
    let code = body.get("code")?.as_str()?;
    let verifier = body.get("code_verifier")?.as_str()?;
    (!code.is_empty() && code.chars().count() <= 128 && verifier.chars().count() <= 128)
        .then_some((code, verifier))
}

fn invalid_grant() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":"invalid_grant"})),
    )
        .into_response()
}

enum Decision {
    Accepted {
        user: Uuid,
        authenticated: DateTime<Utc>,
        provider: String,
        email: Option<String>,
        organization: Option<Uuid>,
    },
    Refused {
        user: Option<Uuid>,
        reason: &'static str,
    },
}

async fn claim(
    tx: &mut Transaction<'_, Postgres>,
    code: &str,
    verifier: &str,
    now: DateTime<Utc>,
) -> Result<Decision, sqlx::Error> {
    let row = sqlx::query("SELECT user_id, provider, authenticated_at, consumed_at, expires_at, code_challenge, id FROM cli_login_codes WHERE code_hash=$1 FOR UPDATE")
        .bind(digest(code)).fetch_optional(&mut **tx).await?;
    let Some(row) = row else {
        return Ok(Decision::Refused {
            user: None,
            reason: "invalid_grant",
        });
    };
    let user: Uuid = row.try_get("user_id")?;
    let refuse = |reason| Decision::Refused {
        user: Some(user),
        reason,
    };
    if row
        .try_get::<Option<DateTime<Utc>>, _>("consumed_at")?
        .is_some()
    {
        return Ok(refuse("replay_detected"));
    }
    if row.try_get::<DateTime<Utc>, _>("expires_at")? <= now {
        return Ok(refuse("expired"));
    }
    sqlx::query("UPDATE cli_login_codes SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL")
        .bind(row.try_get::<Uuid, _>("id")?)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    if !matches_s256(verifier, row.try_get("code_challenge")?) {
        return Ok(refuse("invalid_grant"));
    }
    let account = sqlx::query(
        "SELECT is_active,primary_email,organization_id FROM users WHERE id=$1 FOR SHARE",
    )
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(account) = account else {
        return Ok(refuse("user_not_found"));
    };
    if !account.try_get::<bool, _>("is_active")? {
        return Ok(refuse("inactive"));
    }
    Ok(Decision::Accepted {
        user,
        authenticated: row.try_get("authenticated_at")?,
        provider: row.try_get("provider")?,
        email: account.try_get("primary_email")?,
        organization: account.try_get("organization_id")?,
    })
}

impl Login {
    async fn exchange_cli(
        &self,
        code: &str,
        verifier: &str,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> LoginResult {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();
        let decision = claim(&mut tx, code, verifier, now).await?;
        match decision {
            Decision::Refused { user, reason } => {
                // A refusal consumes a current code even if the audit sink fails.
                tx.commit().await?;
                let event = AuditActivity::CliExchange {
                    provider: None,
                    reason: Some(reason),
                };
                let subject = AuditSubject {
                    user,
                    email: None,
                    organization: None,
                };
                if write_activity(&self.pool, event, subject, origin, request, now)
                    .await
                    .is_err()
                {
                    eprintln!("could not record CLI login code refusal");
                }
                Ok(invalid_grant())
            }
            Decision::Accepted {
                user,
                authenticated,
                provider,
                email,
                organization,
            } => {
                let pair = self
                    .federated_pair(&mut tx, user, authenticated, now)
                    .await?;
                let event = AuditActivity::CliExchange {
                    provider: Some(provider),
                    reason: None,
                };
                let subject = AuditSubject {
                    user: Some(user),
                    email,
                    organization,
                };
                write_activity(&mut *tx, event, subject, origin, request, now).await?;
                tx.commit().await?;
                Ok(Json(json!({
                    "access_token":pair.access_token, "refresh_token":pair.refresh_token,
                    "token_type":"Bearer", "expires_in":self.access.num_seconds()
                }))
                .into_response())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    #[test]
    fn an_empty_verifier_reaches_redemption_and_oversized_fields_do_not() {
        assert_eq!(
            fields(&json!({"code":"a","code_verifier":""})),
            Some(("a", ""))
        );
        assert!(fields(&json!({"code":"","code_verifier":"a"})).is_none());
        assert!(fields(&json!({"code":"a","code_verifier":"é".repeat(129)})).is_none());
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn incorrect_proof_burns_code_only_when_committed() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE cli_login_codes(id uuid,code_hash text,user_id uuid,provider text,authenticated_at timestamptz,consumed_at timestamptz,expires_at timestamptz,code_challenge text);
            CREATE TEMP TABLE users(id uuid,is_active boolean,primary_email text,organization_id uuid);").execute(&pool).await.unwrap();
        let user = Uuid::new_v4();
        let now = Utc::now();
        sqlx::query("INSERT INTO users(id,is_active) VALUES ($1,true)")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO cli_login_codes VALUES($1,$2,$3,'google',$4,NULL,$5,$6)")
            .bind(Uuid::new_v4())
            .bind(digest("code"))
            .bind(user)
            .bind(now)
            .bind(now + TimeDelta::seconds(60))
            .bind(URL_SAFE_NO_PAD.encode(Sha256::digest(b"verifier")))
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(
            matches!(claim(&mut tx,"code","verifier",now).await.unwrap(),Decision::Accepted { user: id, .. } if id==user)
        );
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(matches!(
            claim(&mut tx, "code", "", now).await.unwrap(),
            Decision::Refused {
                reason: "invalid_grant",
                ..
            }
        ));
        tx.commit().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(matches!(
            claim(&mut tx, "code", "verifier", now).await.unwrap(),
            Decision::Refused {
                reason: "replay_detected",
                ..
            }
        ));
    }
}
