use super::*;
use crate::grant_audit::{AuditActivity, AuditSubject, write_activity};

pub(super) async fn apply(
    mut tx: Transaction<'_, Postgres>,
    id: &Identity,
    rp: &str,
    key: Uuid,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let owner = sqlx::query_as::<_, (bool, Option<String>, Option<Uuid>)>(
        "SELECT u.totp_enabled,u.primary_email,u.organization_id FROM passkeys p JOIN users u ON u.id=p.user_id
         WHERE p.id=$1 AND p.user_id=$2 AND p.rp_id=$3 AND p.revoked_at IS NULL FOR UPDATE OF p",
    )
    .bind(key)
    .bind(id.user)
    .bind(rp)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((mfa, email, organization)) = owner else {
        return Ok(problem(StatusCode::NOT_FOUND, "Passkey not found"));
    };
    if !recent(&mut tx, id, mfa).await? {
        return Ok(problem(
            StatusCode::FORBIDDEN,
            "Recent authentication required",
        ));
    }
    let alternative = sqlx::query_scalar::<_, bool>(
        "SELECT (is_email_verified AND coalesce(password_hash,'')<>'')
          OR EXISTS (SELECT FROM passkeys WHERE user_id=$1 AND rp_id=$2 AND id<>$3 AND revoked_at IS NULL)
          OR EXISTS (SELECT FROM user_identities WHERE user_id=$1 AND
                     (type='wallet' OR (type='oauth' AND provider IN ('google','microsoft'))))
         FROM users WHERE id=$1"
    )
    .bind(id.user)
    .bind(rp)
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    if !alternative {
        return Ok(problem(
            StatusCode::CONFLICT,
            "Keep another way to sign in first: verify your email, link Google, Microsoft or a wallet, or add another passkey",
        ));
    }
    let now = Utc::now();
    sqlx::query("UPDATE passkeys SET revoked_at=$2 WHERE id=$1")
        .bind(key)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    write_activity(
        &mut *tx,
        AuditActivity::PasskeyRevoked(key),
        AuditSubject {
            user: Some(id.user),
            email,
            organization,
        },
        origin,
        request_id,
        now,
    )
    .await?;
    commit_response(tx, StatusCode::NO_CONTENT).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn last_key_is_preserved_and_audit_failure_rolls_back_revocation() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid, totp_enabled bool, primary_email text,organization_id uuid,is_email_verified bool,password_hash text);
            CREATE TEMP TABLE sessions(id uuid,user_id uuid,expires_at timestamptz,revoked_at timestamptz,auth_time timestamptz,amr text);
            CREATE TEMP TABLE passkeys(id uuid,user_id uuid,rp_id text,revoked_at timestamptz);
            CREATE TEMP TABLE passkey_reauthentication(session_id uuid,user_id uuid,credential_id uuid,verified_at timestamptz);
            CREATE TEMP TABLE user_identities(user_id uuid,type text,provider text);
            CREATE TEMP TABLE auth_events(id uuid CHECK (id IS NULL));").execute(&pool).await.unwrap();
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        let key = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES ($1,false,NULL,NULL,false,'hash')")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions VALUES ($1,$2,now()+interval '1 hour',NULL,now(),'pwd')")
            .bind(session)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO passkeys VALUES ($1,$2,'app',NULL)")
            .bind(key)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        let identity = Identity {
            user,
            sid: Some(session),
            client_bound: false,
            iat: None,
            jti: Uuid::new_v4(),
        };
        let origin = SessionOrigin {
            ip: None,
            user_agent: None,
        };
        let response = apply(
            pool.begin().await.unwrap(),
            &identity,
            "app",
            key,
            origin,
            None,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        sqlx::query("UPDATE users SET is_email_verified=true")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            apply(
                pool.begin().await.unwrap(),
                &identity,
                "app",
                key,
                origin,
                None
            )
            .await
            .is_err()
        );
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NULL FROM passkeys")
                .fetch_one(&pool)
                .await
                .unwrap()
        );

        sqlx::raw_sql(
            "DROP TABLE pg_temp.auth_events;
            CREATE TEMP TABLE auth_events(activity text UNIQUE DEFERRABLE INITIALLY DEFERRED);
            INSERT INTO auth_events VALUES ('passkey_revoke');",
        )
        .execute(&pool)
        .await
        .unwrap();
        let rejected = apply(
            pool.begin().await.unwrap(),
            &identity,
            "app",
            key,
            origin,
            None,
        )
        .await
        .unwrap();
        assert_eq!(rejected.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let (active, events): (bool, i64) = sqlx::query_as(
            "SELECT revoked_at IS NULL, (SELECT count(*) FROM auth_events) FROM passkeys WHERE id=$1"
        ).bind(key).fetch_one(&pool).await.unwrap();
        assert!(active);
        assert_eq!(events, 1);
        sqlx::query("DELETE FROM auth_events")
            .execute(&pool)
            .await
            .unwrap();
        let retry = apply(
            pool.begin().await.unwrap(),
            &identity,
            "app",
            key,
            origin,
            None,
        )
        .await
        .unwrap();
        assert_eq!(retry.status(), StatusCode::NO_CONTENT);
        let (revoked, events): (bool, i64) = sqlx::query_as(
            "SELECT revoked_at IS NOT NULL, (SELECT count(*) FROM auth_events WHERE activity='passkey_revoke') FROM passkeys WHERE id=$1"
        ).bind(key).fetch_one(&pool).await.unwrap();
        assert!(revoked);
        assert_eq!(events, 1);
    }
}
