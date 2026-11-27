//! Rotate credentials for a first-party browser session.
use super::*;
use crate::{csrf::cookie, mfa_challenges::RefreshIdentity};
use chrono::DateTime;
use std::collections::BTreeSet;

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
    let token = match read_token(&parts.headers, body).await {
        Ok(Some(token)) => token,
        Ok(None) => return problem(StatusCode::UNAUTHORIZED, "Missing refresh token"),
        Err(response) => return *response,
    };
    let origin = SessionOrigin {
        ip: client_ip(&parts.headers, peer.ip(), login.proxies),
        user_agent: header(&parts.headers, "user-agent"),
    };
    let request = header(&parts.headers, "x-request-id");
    let identity = match login.verifier.refresh(&token) {
        Ok(id) => id,
        Err(err) => {
            let reason = err.audit_reason();
            return login.reject_refresh(None, reason, origin, request).await;
        }
    };
    let mut result = login.rotate(identity, origin, request).await;
    // Another writer can take token and session locks in a different order.
    // PostgreSQL has rolled back the victim before reporting a deadlock.
    if let Err(error) = &result
        && error
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|db| db.code())
            .as_deref()
            == Some("40P01")
    {
        result = login.rotate(identity, origin, request).await;
    }
    result.unwrap_or_else(|_| crate::headers::unhandled_error())
}

pub(super) async fn read_token(
    headers: &axum::http::HeaderMap,
    body: axum::body::Body,
) -> Result<Option<String>, Box<Response>> {
    let submitted = input::read(headers, body, &["refresh_token"], input::refresh).await?;
    Ok(cookie(headers, "refresh_token")
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or(submitted)
        .filter(|s| !s.is_empty()))
}

enum Claim {
    Ready {
        next: Uuid,
        auth_time: Option<DateTime<Utc>>,
        amr: Option<String>,
    },
    Refused(&'static str),
    Replay,
}

type Tx<'a> = Transaction<'a, Postgres>;

impl Login {
    async fn rotate(
        &self,
        id: RefreshIdentity,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> LoginResult {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();
        let (next, auth_time, amr) = match claim_refresh(&mut tx, id, now, self.reuse_grace).await?
        {
            Claim::Ready {
                next,
                auth_time,
                amr,
            } => (next, auth_time, amr),
            Claim::Refused(reason) => {
                tx.rollback().await?;
                return Ok(self.reject_refresh(Some(id), reason, origin, request).await);
            }
            Claim::Replay => {
                revoke_family(&mut tx, id).await?;
                tx.commit().await?;
                return Ok(self
                    .reject_refresh(Some(id), "replay_detected", origin, request)
                    .await);
            }
        };
        let account = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
            "SELECT primary_email,organization_id FROM users WHERE id=$1 AND is_active FOR SHARE",
        )
        .bind(id.user)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((email, organization)) = account else {
            tx.rollback().await?;
            return Ok(self
                .reject_refresh(Some(id), "inactive", origin, request)
                .await);
        };
        let policy = LoginPolicy {
            access_lifetime: self.access,
            admin_emails: &self.admins,
            require_verified_admin_email: self.production,
        };
        let methods: Vec<_> = amr
            .as_deref()
            .unwrap_or("")
            .split_ascii_whitespace()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let access = self
            .issuer
            .first_party_access(
                &mut tx,
                (id.user, id.session),
                auth_time,
                &methods,
                &policy,
                now,
            )
            .await?;
        let (refresh, expires) = self
            .issuer
            .refresh_credential(id.user, id.session, next, now)?;
        sqlx::query("INSERT INTO refresh_tokens(jti,session_id,user_id,issued_at,expires_at) VALUES($1,$2,$3,$4,$5)")
            .bind(next).bind(id.session).bind(id.user).bind(now).bind(expires).execute(&mut *tx).await?;
        sqlx::query("UPDATE sessions SET last_used_at=GREATEST(last_used_at,$2) WHERE id=$1")
            .bind(id.session)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        write_activity(
            &mut *tx,
            AuditActivity::Refresh {
                session: Some(id.session),
                reason: None,
            },
            AuditSubject {
                user: Some(id.user),
                email,
                organization,
            },
            origin,
            request,
            now,
        )
        .await?;
        let response = self.token_response(&access, &refresh)?;
        tx.commit().await?;
        Ok(response)
    }

    async fn reject_refresh(
        &self,
        id: Option<RefreshIdentity>,
        reason: &'static str,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> Response {
        let subject = AuditSubject {
            user: id.map(|i| i.user),
            email: None,
            organization: None,
        };
        if write_activity(
            &self.pool,
            AuditActivity::Refresh {
                session: id.map(|i| i.session),
                reason: Some(reason),
            },
            subject,
            origin,
            request,
            Utc::now(),
        )
        .await
        .is_err()
        {
            eprintln!("could not record refresh refusal");
        }
        problem(StatusCode::UNAUTHORIZED, "Invalid refresh token")
    }
}

pub(super) async fn revoke_family(tx: &mut Tx<'_>, id: RefreshIdentity) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2")
        .bind(id.session)
        .bind(id.user)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE refresh_tokens SET revoked_at=now() WHERE session_id=$1 AND user_id=$2 AND revoked_at IS NULL")
        .bind(id.session).bind(id.user).execute(&mut **tx).await?;
    Ok(())
}

async fn claim_refresh(
    tx: &mut Tx<'_>,
    id: RefreshIdentity,
    now: DateTime<Utc>,
    grace: TimeDelta,
) -> Result<Claim, sqlx::Error> {
    type TokenState = (
        Uuid,
        Uuid,
        Option<DateTime<Utc>>,
        Option<Uuid>,
        Option<String>,
    );
    let record = sqlx::query_as::<_,TokenState>(
            "SELECT session_id,user_id,revoked_at,replaced_by_jti,client_id FROM refresh_tokens WHERE jti=$1"
        )
        .bind(id.jti)
        .fetch_optional(&mut **tx)
        .await?;
    type SessionState = (Option<DateTime<Utc>>, Option<String>, Option<DateTime<Utc>>);
    let session_state = sqlx::query_as::<_, SessionState>(
        "SELECT auth_time,amr,revoked_at FROM sessions WHERE id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(id.session)
    .bind(id.user)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((session, user, revoked, replacement, client)) = record else {
        return Ok(Claim::Replay);
    };
    if (session, user) != (id.session, id.user) {
        return Ok(Claim::Refused("invalid_token"));
    }
    if let Some(at) = revoked {
        if !matches!(session_state, Some((_, _, None))) {
            return Ok(Claim::Refused("revoked"));
        }
        if grace > TimeDelta::zero() && now - at <= grace {
            let known = sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM refresh_tokens WHERE jti=$1 AND session_id=$2 AND user_id=$3)")
                    .bind(replacement).bind(session).bind(user).fetch_one(&mut **tx).await?;
            if known {
                return Ok(Claim::Refused("concurrent_refresh"));
            }
        }
        return Ok(Claim::Replay);
    }
    if client.is_some() {
        return Ok(Claim::Refused("client_mismatch"));
    }
    let Some((auth_time, amr, None)) = session_state else {
        return Ok(Claim::Refused("revoked"));
    };
    let next = Uuid::new_v4();
    let claimed = sqlx::query("UPDATE refresh_tokens SET revoked_at=$2,replaced_by_jti=$3 WHERE jti=$1 AND revoked_at IS NULL")
            .bind(id.jti).bind(now).bind(next).execute(&mut **tx).await?;
    Ok(if claimed.rows_affected() == 1 {
        Claim::Ready {
            next,
            auth_time,
            amr,
        }
    } else {
        Claim::Refused("concurrent_refresh")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn claim_and_replay_preserve_the_session_boundary() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE sessions(id uuid,user_id uuid,auth_time timestamptz,amr text,revoked_at timestamptz);
             CREATE TEMP TABLE refresh_tokens(jti uuid,session_id uuid,user_id uuid,revoked_at timestamptz,replaced_by_jti uuid,client_id text);"
        ).execute(&mut *tx).await.unwrap();
        let id = RefreshIdentity {
            user: Uuid::new_v4(),
            session: Uuid::new_v4(),
            jti: Uuid::new_v4(),
        };
        sqlx::query("INSERT INTO sessions VALUES ($1,$2,NULL,NULL,NULL)")
            .bind(id.session)
            .bind(id.user)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO refresh_tokens VALUES ($1,$2,$3,NULL,NULL,NULL)")
            .bind(id.jti)
            .bind(id.session)
            .bind(id.user)
            .execute(&mut *tx)
            .await
            .unwrap();
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let grace = TimeDelta::seconds(10);
        let Claim::Ready {
            next,
            auth_time: None,
            ..
        } = claim_refresh(&mut tx, id, now, grace).await.unwrap()
        else {
            panic!("live credential refused")
        };
        assert!(matches!(
            claim_refresh(&mut tx, id, now, grace).await.unwrap(),
            Claim::Replay
        ));
        sqlx::query("INSERT INTO refresh_tokens VALUES ($1,$2,$3,NULL,NULL,NULL)")
            .bind(next)
            .bind(id.session)
            .bind(id.user)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(matches!(
            claim_refresh(&mut tx, id, now + grace, grace)
                .await
                .unwrap(),
            Claim::Refused("concurrent_refresh")
        ));
        assert!(matches!(
            claim_refresh(&mut tx, id, now, TimeDelta::zero())
                .await
                .unwrap(),
            Claim::Replay
        ));
        assert!(matches!(
            claim_refresh(&mut tx, id, now + grace + TimeDelta::seconds(1), grace)
                .await
                .unwrap(),
            Claim::Replay
        ));
        revoke_family(&mut tx, id).await.unwrap();
        let child = RefreshIdentity { jti: next, ..id };
        assert!(matches!(
            claim_refresh(&mut tx, child, now, grace).await.unwrap(),
            Claim::Refused("revoked")
        ));
        tx.rollback().await.unwrap();
    }
}
