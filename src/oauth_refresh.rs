//! Rotate a client-authenticated OAuth refresh grant in the caller's transaction.
use crate::{
    browser_client::grant::ResourceScopes,
    grant_sessions::{GrantSessionIssuer, SessionError},
    mfa_challenges::{ChallengeVerifier, RefreshIdentity},
};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

pub struct RefreshRequest<'a> {
    pub token: &'a str,
    pub client: &'a str,
    pub client_scopes: &'a str,
    pub requested_scopes: Option<&'a str>,
    pub requested_resources: &'a [String],
    pub registry: &'a ResourceScopes,
}

pub struct Rotation {
    pub token: String,
    pub user: Uuid,
    pub session: Uuid,
    pub client: Option<String>,
    pub resource: Option<String>,
    pub scopes: String,
    pub auth_time: Option<DateTime<Utc>>,
    pub amr: Option<String>,
}
pub struct Refused {
    pub user: Option<Uuid>,
    pub reason: &'static str,
    pub description: &'static str,
}

impl Refused {
    fn known(id: RefreshIdentity, reason: &'static str, description: &'static str) -> Self {
        Self {
            user: Some(id.user),
            reason,
            description,
        }
    }
}

const USED: &str = "refresh token already used or unknown";

async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    id: RefreshIdentity,
    now: DateTime<Utc>,
) -> Result<Refused, sqlx::Error> {
    let revoked = sqlx::query_scalar::<_, bool>(
        "SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(id.session)
    .bind(id.user)
    .fetch_optional(&mut **tx)
    .await?;
    if revoked == Some(true) {
        return Ok(Refused::known(id, "revoked", USED));
    }
    if revoked == Some(false) {
        crate::token_revocation::revoke_session(tx, id.session, now).await?;
    }
    Ok(Refused::known(id, "replay_detected", USED))
}

fn granted_scopes(
    req: &RefreshRequest<'_>,
    original: Option<&str>,
    resource: Option<&str>,
) -> String {
    let allowed: BTreeSet<_> = req.client_scopes.split_whitespace().collect();
    let consent = original
        .filter(|s| !s.is_empty())
        .unwrap_or(req.client_scopes);
    let requested: BTreeSet<_> = req
        .requested_scopes
        .filter(|s| !s.is_empty())
        .unwrap_or(consent)
        .split_whitespace()
        .collect();
    let resource_scopes = resource.and_then(|uri| req.registry.get(uri));
    let consent: BTreeSet<_> = consent.split_whitespace().collect();
    requested
        .intersection(&consent)
        .copied()
        .filter(|s| allowed.contains(*s))
        .filter(|s| {
            resource_scopes.is_none_or(|set| {
                matches!(*s, "openid" | "email" | "profile" | "offline_access") || set.contains(*s)
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl GrantSessionIssuer {
    /// Authenticate the client and authorize its refresh grant before calling. Commit a replay
    /// refusal to persist family revocation. Sign the access/ID tokens and audit before commit.
    pub async fn rotate_oauth_refresh(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        verifier: &ChallengeVerifier,
        req: &RefreshRequest<'_>,
        now: DateTime<Utc>,
    ) -> Result<Result<Rotation, Refused>, SessionError> {
        let id = match verifier.refresh(req.token) {
            Ok(id) => id,
            Err(error) => {
                return Ok(Err(Refused {
                    user: None,
                    reason: error.audit_reason(),
                    description: "invalid refresh token",
                }));
            }
        };
        let row=sqlx::query("SELECT user_id,session_id,revoked_at IS NOT NULL AS used,client_id,resource,scopes FROM refresh_tokens WHERE jti=$1")
            .bind(id.jti).fetch_optional(&mut **tx).await?;
        let Some(row) = row else {
            return Ok(Err(replay(tx, id, now).await?));
        };
        if row.try_get::<Uuid, _>("user_id")? != id.user
            || row.try_get::<Uuid, _>("session_id")? != id.session
        {
            return Ok(Err(Refused::known(
                id,
                "invalid_token",
                "invalid refresh token",
            )));
        }
        if row.try_get("used")? {
            return Ok(Err(replay(tx, id, now).await?));
        }
        let client = row.try_get::<Option<String>, _>("client_id")?;
        let resource = row.try_get::<Option<String>, _>("resource")?;
        if client.as_deref().is_some_and(|owner| owner != req.client) {
            return Ok(Err(Refused::known(
                id,
                "client_mismatch",
                "refresh token was issued to another client",
            )));
        }
        if !crate::code_exchange::resource_matches(req.requested_resources, resource.as_deref()) {
            return Ok(Err(Refused::known(
                id,
                "invalid_target",
                "resource does not match the authorization grant",
            )));
        }
        let session=sqlx::query("SELECT auth_time,amr FROM sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL FOR UPDATE")
            .bind(id.session).bind(id.user).fetch_optional(&mut **tx).await?;
        let Some(session) = session else {
            return Ok(Err(Refused::known(id, "revoked", "session revoked")));
        };
        let active =
            sqlx::query_scalar::<_, bool>("SELECT is_active FROM users WHERE id=$1 FOR SHARE")
                .bind(id.user)
                .fetch_optional(&mut **tx)
                .await?;
        if active != Some(true) {
            return Ok(Err(Refused::known(id, "inactive", "user unavailable")));
        }
        if client.is_some()
            && resource
                .as_ref()
                .is_some_and(|uri| !req.registry.contains_key(uri))
        {
            return Ok(Err(Refused::known(
                id,
                "invalid_grant",
                "the grant's resource is no longer available",
            )));
        }
        let original = row.try_get::<Option<&str>, _>("scopes")?;
        let scopes = granted_scopes(req, original, resource.as_deref());
        let next = Uuid::new_v4();
        let changed=sqlx::query("UPDATE refresh_tokens SET revoked_at=$2,replaced_by_jti=$3 WHERE jti=$1 AND revoked_at IS NULL")
            .bind(id.jti).bind(now).bind(next).execute(&mut **tx).await?;
        if changed.rows_affected() == 0 {
            return Ok(Err(Refused::known(id, "concurrent_refresh", USED)));
        }
        let (token, expires) = self.refresh_credential(id.user, id.session, next, now)?;
        sqlx::query("INSERT INTO refresh_tokens(jti,session_id,user_id,issued_at,expires_at,client_id,resource,scopes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(next).bind(id.session).bind(id.user).bind(now).bind(expires).bind(&client).bind(&resource).bind(original).execute(&mut **tx).await?;
        Ok(Ok(Rotation {
            token,
            user: id.user,
            session: id.session,
            auth_time: session.try_get("auth_time")?,
            amr: session.try_get("amr")?,
            client,
            resource,
            scopes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::SigningIdentity;
    use chrono::TimeDelta;
    use sqlx::postgres::PgPoolOptions;

    const TABLES:&str="CREATE TABLE users(id uuid, is_active bool);
            CREATE TABLE sessions(id uuid,user_id uuid,auth_time timestamptz,amr text,revoked_at timestamptz);
            CREATE TABLE refresh_tokens(jti uuid PRIMARY KEY,session_id uuid,user_id uuid,issued_at timestamptz,expires_at timestamptz,
                client_id text,resource text,scopes text,revoked_at timestamptz,replaced_by_jti uuid);";
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn rotation_keeps_original_consent_and_rolls_back_with_its_transaction() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql(&TABLES.replace("CREATE TABLE", "CREATE TEMP TABLE"))
            .execute(&pool)
            .await
            .unwrap();
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        let jti = Uuid::new_v4();
        let now = Utc::now();
        sqlx::query("INSERT INTO users VALUES($1,true)")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions VALUES($1,$2,$3,'pwd',NULL)")
            .bind(session)
            .bind(user)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO refresh_tokens(jti,session_id,user_id,client_id,scopes,resource) VALUES($1,$2,$3,'app','openid read','api')").bind(jti).bind(session).bind(user).execute(&pool).await.unwrap();
        let issuer = GrantSessionIssuer::with_identity(
            SigningIdentity::hmac("issuer".into(), b"fixture").unwrap(),
            TimeDelta::days(1),
        )
        .unwrap();
        let verifier = ChallengeVerifier::hmac("issuer", b"fixture").unwrap();
        let (raw, _) = issuer.refresh_credential(user, session, jti, now).unwrap();
        let registry = ResourceScopes::from([("api".into(), BTreeSet::from(["read".into()]))]);
        let mut req = RefreshRequest {
            token: &raw,
            client: "app",
            client_scopes: "openid read write",
            requested_scopes: Some("read write"),
            requested_resources: &[],
            registry: &registry,
        };
        let mut tx = pool.begin().await.unwrap();
        let result = issuer
            .rotate_oauth_refresh(&mut tx, &verifier, &req, now)
            .await
            .unwrap()
            .ok()
            .unwrap();
        assert_eq!(result.scopes, "read");
        assert_eq!(result.session, session);
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        let rotation = issuer
            .rotate_oauth_refresh(&mut tx, &verifier, &req, now)
            .await
            .unwrap()
            .ok()
            .unwrap();
        req.token = &rotation.token;
        req.requested_scopes = None;
        let restored = issuer
            .rotate_oauth_refresh(&mut tx, &verifier, &req, now)
            .await
            .unwrap()
            .ok()
            .unwrap();
        assert_eq!(restored.scopes, "openid read");
        assert_eq!(restored.resource.as_deref(), Some("api"));
        req.token = &raw;
        let replay = issuer
            .rotate_oauth_refresh(&mut tx, &verifier, &req, now)
            .await
            .unwrap()
            .err()
            .unwrap();
        assert_eq!(replay.reason, "replay_detected");
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NOT NULL FROM sessions")
                .fetch_one(&pool)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn overlapping_rotations_issue_one_replacement_without_ending_the_session() {
        let db = std::env::var("DATABASE_URL").unwrap();
        let admin = sqlx::PgPool::connect(&db).await.unwrap();
        let schema = format!("rotate_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |conn, _| {
                let path = path.clone();
                Box::pin(async move { sqlx::query(&path).execute(conn).await.map(|_| ()) })
            })
            .connect(&db)
            .await
            .unwrap();
        sqlx::raw_sql(TABLES).execute(&pool).await.unwrap();
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        let jti = Uuid::new_v4();
        let now = Utc::now();
        sqlx::query("INSERT INTO users VALUES ($1,true)")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions VALUES ($1,$2,$3,'pwd',NULL)")
            .bind(session)
            .bind(user)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO refresh_tokens(jti,user_id,session_id,client_id) VALUES ($1,$2,$3,'app')",
        )
        .bind(jti)
        .bind(user)
        .bind(session)
        .execute(&pool)
        .await
        .unwrap();
        let mut gate = pool.begin().await.unwrap();
        let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid() FROM sessions FOR UPDATE")
            .fetch_one(&mut *gate)
            .await
            .unwrap();
        let issuer = GrantSessionIssuer::with_identity(
            SigningIdentity::hmac("issuer".into(), b"key").unwrap(),
            TimeDelta::days(1),
        )
        .unwrap();
        let verifier = ChallengeVerifier::hmac("issuer", b"key").unwrap();
        let (raw, _) = issuer.refresh_credential(user, session, jti, now).unwrap();
        let registry = ResourceScopes::new();
        let req = RefreshRequest {
            token: &raw,
            client: "app",
            client_scopes: "read",
            requested_resources: &[],
            requested_scopes: None,
            registry: &registry,
        };
        let attempt = || async {
            let mut tx = pool.begin().await.unwrap();
            let result = issuer
                .rotate_oauth_refresh(&mut tx, &verifier, &req, now)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            result.err().map(|e| e.reason)
        };
        let release = async {
            // Both clients must have read the old token before we release the session lock.
            tokio::time::timeout(std::time::Duration::from_secs(10),async{
                loop{
                    let waiting=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'
                        AND ( $1=ANY(pg_blocking_pids(pid)) OR EXISTS(SELECT 1 FROM unnest(pg_blocking_pids(pid)) blocked_by WHERE $1=ANY(pg_blocking_pids(blocked_by))))")
                        .bind(pid).fetch_one(&admin).await.unwrap();
                    if waiting>=2{break;}
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }).await.unwrap();
            gate.commit().await.unwrap();
        };
        let (one, two, ()) = tokio::join!(attempt(), attempt(), release);
        let mut outcomes = [one, two];
        outcomes.sort();
        assert_eq!(outcomes, [None, Some("concurrent_refresh")]);
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NULL FROM sessions")
                .fetch_one(&pool)
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }
}
