//! One-time disclosure of a replacement OAuth client secret.
use super::*;
use crate::{passwords::PasswordScheme, request_json};
use axum::body::Bytes;

pub(in crate::profile) async fn rotate(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(target): Path<String>,
    bytes: Bytes,
) -> Response {
    if method != Method::POST {
        return crate::token_http::post_only().await;
    }
    let body = if bytes.is_empty() || request_json::is_json(&headers) {
        let Ok(text) = request_json::encoding::text(&bytes) else {
            return problem(
                StatusCode::BAD_REQUEST,
                "There was an error parsing the body",
            );
        };
        match request_json::parse_body(&headers, text.as_bytes()) {
            Ok(value) => Some(value),
            Err(issue) => return invalid(issue),
        }
    } else {
        None
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: header_value(&headers, "user-agent"),
    };
    handle(&state, &headers, Operation::Rotate(&target, body, origin)).await
}

fn invalid(issue: Value) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail":[issue]})),
    )
        .into_response()
}
fn integer(input: &Value) -> Result<i128, (&'static str, &'static str)> {
    match input {
        Value::Bool(v) => Ok(i128::from(*v)),
        Value::String(s) => {
            let digits = crate::query::integer(s)?;
            Ok(digits.parse().unwrap_or_else(|_| {
                if digits.starts_with('-') {
                    i128::MIN
                } else {
                    i128::MAX
                }
            }))
        }
        Value::Number(n) => {
            if let Some(v) = n.as_i64() {
                return Ok(i128::from(v));
            }
            if let Some(v) = n.as_u64() {
                return Ok(i128::from(v));
            }
            let v = n.as_f64().unwrap_or(f64::NAN);
            if v.fract() == 0.0 {
                Ok(v as i128)
            } else {
                Err((
                    "int_from_float",
                    "Input should be a valid integer, got a number with a fractional part",
                ))
            }
        }
        _ => Err(("int_type", "Input should be a valid integer")),
    }
}
fn grace(body: Value) -> Result<i32, Value> {
    if body.is_null() {
        return Ok(300);
    }
    let Some(fields) = body.as_object() else {
        return Err(
            json!({"type":"model_attributes_type","loc":["body"],"msg":"Input should be a valid dictionary or object to extract fields from","input":body}),
        );
    };
    let Some(value) = fields.get("grace_seconds") else {
        return Ok(300);
    };
    let error = |kind: &str, msg: &str| json!({"type":kind,"loc":["body","grace_seconds"],"msg":msg,"input":value});
    let n = integer(value).map_err(|(k, m)| error(k, m))?;
    let (mut issue, ctx) = match n {
        0..=3600 => return Ok(n as i32),
        ..0 => (
            error(
                "greater_than_equal",
                "Input should be greater than or equal to 0",
            ),
            json!({"ge":"0"}),
        ),
        _ => (
            error(
                "less_than_equal",
                "Input should be less than or equal to 3600",
            ),
            json!({"le":"3600"}),
        ),
    };
    issue["ctx"] = ctx;
    Err(issue)
}

pub(super) async fn apply(
    mut tx: Transaction<'_, Postgres>,
    actor: (Uuid, Option<&str>),
    target: &str,
    body: Option<Value>,
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let Some(body) = body else {
        return Ok(internal());
    };
    let seconds = match grace(body) {
        Ok(n) => n,
        Err(issue) => return Ok(invalid(issue)),
    };
    let locked = sqlx::query("SELECT 1 FROM oauth_clients WHERE client_id=$1 FOR UPDATE")
        .bind(target)
        .fetch_optional(&mut *tx)
        .await?;
    if locked.is_none() {
        return Ok(problem(StatusCode::NOT_FOUND, "OAuth client not found"));
    }
    let deadline = Utc::now() + chrono::Duration::seconds(i64::from(seconds));
    let secret = crate::client_auth::opaque::<32>();
    let hash = PasswordScheme::Argon2
        .hash(secret.clone())
        .await
        .map_err(|_| sqlx::Error::WorkerCrashed)?;
    let row = sqlx::query(&format!(
        "UPDATE oauth_clients SET previous_secret_hash=secret_hash,
        previous_secret_expires_at=$2,
        secret_hash=$3, updated_at=now() WHERE client_id=$1 RETURNING {COLUMNS}"
    ))
    .bind(target)
    .bind(deadline)
    .bind(hash)
    .fetch_one(&mut *tx)
    .await?;
    let client = item(row)?;
    crate::admin_audit::append_client_action(
        &mut tx,
        "oauth_client.rotate_secret",
        Some(actor),
        target,
        json!({"grace_seconds":seconds}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"client":client,"client_secret":secret})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_and_zero_grace_have_distinct_effects() {
        assert_eq!(grace(Value::Null).unwrap(), 300);
        assert_eq!(grace(json!({})).unwrap(), 300);
        assert_eq!(grace(json!({"grace_seconds":0})).unwrap(), 0);
        assert_eq!(grace(json!({"grace_seconds":"3600.00"})).unwrap(), 3600);
        for (value, kind) in [
            (Value::Null, "int_type"),
            (json!(-1), "greater_than_equal"),
            (json!(3601), "less_than_equal"),
            (json!(0.5), "int_from_float"),
        ] {
            assert_eq!(
                grace(json!({"grace_seconds":value})).unwrap_err()["type"],
                kind
            );
        }
    }
}
