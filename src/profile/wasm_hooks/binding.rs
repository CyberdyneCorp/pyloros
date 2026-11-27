use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem};
use axum::{body::Bytes, extract::Path};

fn reply(id: Uuid, digest: Option<&str>) -> Response {
    Json(json!({"hook_id":id, "sha256":digest})).into_response()
}

fn hook_id(raw: &str) -> Result<Uuid, Box<Response>> {
    crate::query::path_uuid(raw, "hook_id").map_err(|e| Box::new(passkeys::validation(vec![e])))
}

pub(in crate::profile) async fn read(
    State(state): State<Arc<Profile>>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(session) => session,
        Err(e) => return *e,
    };
    let id = match hook_id(&raw) {
        Ok(id) => id,
        Err(e) => return *e,
    };
    let result = sqlx::query_scalar::<_,Option<String>>(
        "SELECT b.sha256 FROM hooks h LEFT JOIN pyloros_hook_bindings b ON h.id=b.hook_id WHERE h.id=$1",
    ).bind(id).fetch_optional(&mut *tx).await;
    match result {
        Ok(Some(digest)) => reply(id, digest.as_deref()),
        Ok(None) => problem(StatusCode::NOT_FOUND, "Hook not found"),
        Err(_) => internal(),
    }
}

pub(in crate::profile) async fn write(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: Bytes,
) -> Response {
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(session) => session,
        Err(e) => return *e,
    };
    let id = match hook_id(&raw) {
        Ok(id) => id,
        Err(e) => return *e,
    };
    let digest = if method == Method::PUT {
        if !crate::request_json::is_json(&headers) {
            return problem(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Expected application/json",
            );
        }
        #[derive(Deserialize)]
        struct Binding {
            sha256: String,
        }
        let Ok(binding) = serde_json::from_slice::<Binding>(&bytes) else {
            return problem(StatusCode::UNPROCESSABLE_ENTITY, "Expected a sha256 digest");
        };
        if binding.sha256.len() != 64
            || !binding
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Expected a lowercase SHA-256 digest",
            );
        }
        Some(binding.sha256)
    } else {
        None
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    change(tx, id, digest.as_deref(), (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn change(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    digest: Option<&str>,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> sqlx::Result<Response> {
    let hook = sqlx::query_scalar::<_, Uuid>("SELECT id FROM hooks WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    if hook.is_none() {
        return Ok(problem(StatusCode::NOT_FOUND, "Hook not found"));
    }
    let previous = sqlx::query_scalar::<_, String>(
        "SELECT sha256 FROM pyloros_hook_bindings WHERE hook_id=$1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if previous.as_deref() == digest {
        return Ok(reply(id, digest));
    }
    if let Some(digest) = digest {
        let rows = sqlx::query(
            "INSERT INTO pyloros_hook_bindings(hook_id,sha256)
            SELECT $1,sha256 FROM pyloros_hook_artifacts WHERE sha256=$2
            ON CONFLICT (hook_id) DO UPDATE SET sha256=excluded.sha256",
        )
        .bind(id)
        .bind(digest)
        .execute(&mut *tx)
        .await?;
        if rows.rows_affected() == 0 {
            return Ok(problem(StatusCode::NOT_FOUND, "Hook artifact not found"));
        }
    } else {
        sqlx::query("DELETE FROM pyloros_hook_bindings WHERE hook_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    crate::admin_audit::append(
        &mut tx,
        "hook.binding.update",
        Some(actor),
        ("hook", &id.to_string()),
        json!({"previous_sha256":previous,"sha256":digest}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(reply(id, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn audit_failure_preserves_the_selected_version() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE hooks(id uuid PRIMARY KEY);
            CREATE TEMP TABLE pyloros_hook_artifacts(sha256 text PRIMARY KEY);
            CREATE TEMP TABLE audit_chain_head(id int PRIMARY KEY,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text CHECK(action <> 'hook.binding.update'),
            target_type text,target_id text,extra_metadata jsonb,ip_address inet,user_agent text,
            created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_type text,
            actor_client_id text,actor_email text);").execute(&pool).await.unwrap();
        let ddl = include_str!("../../../migrations/002_hook_bindings.sql")
            .replace("CREATE TABLE", "CREATE TEMP TABLE");
        sqlx::raw_sql(&ddl).execute(&pool).await.unwrap();
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO hooks VALUES ($1)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO pyloros_hook_artifacts VALUES ('first'),('second')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO pyloros_hook_bindings VALUES ($1,'first')")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let result = change(
            pool.begin().await.unwrap(),
            id,
            Some("second"),
            (Uuid::new_v4(), None),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await;
        assert_eq!(
            result
                .unwrap_err()
                .as_database_error()
                .unwrap()
                .code()
                .as_deref(),
            Some("23514")
        );
        let selected: String =
            sqlx::query_scalar("SELECT sha256 FROM pyloros_hook_bindings WHERE hook_id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(selected, "first");
    }
}
