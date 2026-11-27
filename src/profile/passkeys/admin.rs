//! Account-wide credential metadata for the administrative user detail screen.
use super::*;
use axum::extract::Path;
use sqlx::Row;

#[derive(Serialize)]
struct AdminRecord {
    rp_id: String,
    #[serde(flatten)]
    key: Record,
}

pub(in crate::profile) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (mut tx, user) = match admin_users::target(&state, &method, &headers, &raw).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    inventory(&mut tx, user)
        .await
        .unwrap_or_else(|_| internal())
}

async fn inventory(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Response, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
    if !exists {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    }
    let keys = sqlx::query(
        "SELECT id,rp_id,name,created_at,last_used_at,backup_eligible,backed_up FROM passkeys
         WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(user)
    .try_map(|row| {
        Ok(AdminRecord {
            rp_id: row.try_get("rp_id")?,
            key: record(row)?,
        })
    })
    .fetch_all(&mut **tx)
    .await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(keys)).into_response())
}

pub(in crate::profile) async fn revoke(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((user, key)): Path<(String, String)>,
) -> Response {
    if method != Method::DELETE {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return r;
    }
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let user = crate::query::path_uuid(&user, "user_id");
    let key = crate::query::path_uuid(&key, "passkey_id");
    let (user, key) = match (user, key) {
        (Ok(user), Ok(key)) => (user, key),
        (user, key) => return validation([user.err(), key.err()].into_iter().flatten().collect()),
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: header_value(&headers, "user-agent"),
    };
    remove(
        tx,
        user,
        key,
        (actor, email.as_deref()),
        origin,
        header_value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn remove(
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    key: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, sqlx::Error> {
    use crate::grant_audit::{AuditActivity, AuditSubject, write_activity};
    let subject = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
        "SELECT primary_email,organization_id FROM users WHERE id=$1",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, organization)) = subject else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    let now = Utc::now();
    let name = revoke_observed(&mut tx, user, key, now).await?;
    let Some(name) = name else {
        return Ok(problem(StatusCode::NOT_FOUND, "Passkey not found"));
    };
    write_activity(
        &mut *tx,
        AuditActivity::AdminPasskeyRevoked {
            operator: actor.0,
            key,
        },
        AuditSubject {
            user: Some(user),
            email,
            organization,
        },
        origin,
        request,
        now,
    )
    .await?;
    crate::admin_audit::append(
        &mut tx,
        "user.revoke_passkey",
        Some(actor),
        ("user", &user.to_string()),
        json!({"passkey_id":key,"name":name}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn revoke_observed(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    key: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<String>, sqlx::Error> {
    // Preserve the metadata observed by this revocation if a rename or assertion
    // finishes while the update waits. Both the stored record and audit use it.
    sqlx::query_scalar::<_, String>(
        "WITH observed AS MATERIALIZED (
             SELECT id,name,sign_count,backed_up,last_used_at FROM passkeys
             WHERE user_id=$1 AND id=$2 AND revoked_at IS NULL
         )
         UPDATE passkeys p SET revoked_at=$3,name=o.name,sign_count=o.sign_count,
             backed_up=o.backed_up,last_used_at=o.last_used_at
         FROM observed o WHERE p.id=o.id RETURNING o.name",
    )
    .bind(user)
    .bind(key)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn revocation_retains_the_metadata_read_before_a_concurrent_update() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let schema = format!("test_passkeys_{}", Uuid::new_v4().simple());
        let path = format!("SET LOCAL search_path TO {schema}");
        let mut setup = pool.begin().await.unwrap();
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut *setup)
            .await
            .unwrap();
        sqlx::query(&path).execute(&mut *setup).await.unwrap();
        sqlx::query("CREATE TABLE passkeys (id uuid PRIMARY KEY,user_id uuid,name text,sign_count bigint,backed_up boolean,last_used_at timestamptz,revoked_at timestamptz)").execute(&mut *setup).await.unwrap();
        let user = Uuid::new_v4();
        let key = Uuid::new_v4();
        sqlx::query("INSERT INTO passkeys VALUES ($1,$2,'original',1,false,NULL,NULL)")
            .bind(key)
            .bind(user)
            .execute(&mut *setup)
            .await
            .unwrap();
        setup.commit().await.unwrap();

        let mut rename = pool.begin().await.unwrap();
        sqlx::query(&path).execute(&mut *rename).await.unwrap();
        sqlx::query(
            "UPDATE passkeys SET name='changed',sign_count=2,backed_up=true,last_used_at=now()",
        )
        .execute(&mut *rename)
        .await
        .unwrap();
        let mut revocation = pool.begin().await.unwrap();
        sqlx::query(&path).execute(&mut *revocation).await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *revocation)
            .await
            .unwrap();
        let writer = tokio::spawn(async move {
            let name = revoke_observed(&mut revocation, user, key, Utc::now())
                .await
                .unwrap();
            revocation.commit().await.unwrap();
            name
        });
        let blocked = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let waiting: bool =
                    sqlx::query_scalar("SELECT pg_backend_pid() = ANY(pg_blocking_pids($1))")
                        .bind(pid)
                        .fetch_one(&mut *rename)
                        .await
                        .unwrap();
                if waiting {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        rename.commit().await.unwrap();
        let observed = writer.await.unwrap();
        let mut cleanup = pool.begin().await.unwrap();
        sqlx::query(&path).execute(&mut *cleanup).await.unwrap();
        let row: (String,i64,bool,bool,bool) = sqlx::query_as("SELECT name,sign_count,backed_up,last_used_at IS NULL,revoked_at IS NOT NULL FROM passkeys").fetch_one(&mut *cleanup).await.unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&mut *cleanup)
            .await
            .unwrap();
        cleanup.commit().await.unwrap();
        blocked.expect("revocation must observe the row before the rename commits");
        assert_eq!(observed.as_deref(), Some("original"));
        assert_eq!(row, ("original".into(), 1, false, true, true));
    }
}
