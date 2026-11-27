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

fn uuid_reason(path: &str, error: uuid::Error) -> String {
    if path.bytes().all(|c| c.is_ascii_hexdigit()) {
        return format!(
            "invalid length: expected length 32 for simple format, found {}",
            path.len()
        );
    }
    let message = error.to_string();
    if message.starts_with("invalid character:")
        && let Some((prefix, offset)) = message.rsplit_once(" at ")
        && let Ok(index) = offset.parse::<usize>()
    {
        return format!("{prefix} at {}", index + 1);
    }
    message
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
    Uuid::parse_str(path).map_err(|error| {
        let reason = uuid_reason(path, error);
        json!({
            "type":"uuid_parsing", "loc":["path","passkey_id"],
            "msg":format!("Input should be a valid UUID, {reason}"),
            "input":path, "ctx":{"error":reason}
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
