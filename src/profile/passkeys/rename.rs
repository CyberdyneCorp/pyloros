use super::*;
use crate::request_json::{parse_body, token_field};

pub(super) async fn handle(
    state: &Profile,
    peer: SocketAddr,
    path: String,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 2 * 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let body = match parse_body(&parts.headers, &bytes) {
        Ok(body) => body,
        Err(issue) => return validation(vec![issue]),
    };
    run(
        state,
        &parts.headers,
        peer.ip(),
        Operation::Rename(input(&path, body)),
    )
    .await
}

fn input(path: &str, body: Value) -> Result<(Uuid, String), Vec<Value>> {
    let id = key_id(path);
    let name = token_field(body, "name", 1, 64).and_then(|raw| {
        let trimmed = raw.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c));
        if trimmed.is_empty() {
            return Err(json!({
                "loc":["body","name"], "type":"value_error", "msg":"Value error, Name cannot be blank",
                "input":raw, "ctx":{"error":"Name cannot be blank"}
            }));
        }
        Ok(trimmed.to_owned())
    });
    match (id, name) {
        (Ok(id), Ok(name)) => Ok((id, name)),
        (id, name) => Err(id.err().into_iter().chain(name.err()).collect()),
    }
}

pub(super) async fn apply(
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    rp: &str,
    key: Uuid,
    name: String,
) -> Result<Response, sqlx::Error> {
    let record = match save(&mut tx, user, rp, key, name).await {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(problem(StatusCode::NOT_FOUND, "Passkey not found")),
        Err(sqlx::Error::Database(error))
            if error.code().is_some_and(|code| code.starts_with("22")) =>
        {
            return Ok(internal());
        }
        Err(error) => return Err(error),
    };
    commit_response(tx, Json(record)).await
}

pub(super) async fn save(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    rp: &str,
    key: Uuid,
    name: String,
) -> Result<Option<Record>, sqlx::Error> {
    sqlx::query(
        "UPDATE passkeys SET name=$4 WHERE id=$1 AND user_id=$2 AND rp_id=$3 AND revoked_at IS NULL
         RETURNING id,name,created_at,last_used_at,backup_eligible,backed_up",
    )
    .bind(key)
    .bind(user)
    .bind(rp)
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?
    .map(record)
    .transpose()
}

pub(super) fn key_id(path: &str) -> Result<Uuid, Value> {
    crate::query::path_uuid(path, "passkey_id")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn rejected_rename_keeps_the_committed_name() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE passkeys (id uuid, user_id uuid, rp_id text, name text UNIQUE DEFERRABLE INITIALLY DEFERRED, created_at timestamptz DEFAULT now(), last_used_at timestamptz, backup_eligible bool DEFAULT false, backed_up bool DEFAULT false, revoked_at timestamptz)")
            .execute(&pool).await.unwrap();
        let key = Uuid::new_v4();
        sqlx::query("INSERT INTO passkeys(id,user_id,rp_id,name) VALUES ($1,$1,'test','first'),($2,$1,'test','second')")
            .bind(key).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
        let response = apply(
            pool.begin().await.unwrap(),
            key,
            "test",
            key,
            "second".into(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let stored: String = sqlx::query_scalar("SELECT name FROM passkeys WHERE id=$1")
            .bind(key)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, "first");
        let retry = apply(
            pool.begin().await.unwrap(),
            key,
            "test",
            key,
            "renamed".into(),
        )
        .await
        .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
    }

    #[test]
    fn rename_checks_character_count_before_trimming() {
        let id = Uuid::new_v4();
        let path = id.to_string();
        assert!(input(&path, json!({"name":"α".repeat(65)})).is_err());
        assert!(input(&path, json!({"name":" ".repeat(64)})).is_err());
        assert_eq!(
            input(&path, json!({"name":format!(" {} ","α".repeat(62))})).unwrap(),
            (id, "α".repeat(62))
        );
        let errors = input("wrong-id", json!({})).unwrap_err();
        assert_eq!(errors.len(), 2);
        assert_eq!(
            errors[0]["ctx"]["error"],
            "invalid character: found `w` at 1"
        );
    }
}
