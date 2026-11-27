//! Read and update the password sign-in email confirmation policy.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem};

const INVALID: &str = "Use \"never\" or a duration from 1h to 30d, such as \"7d\"";
const UNAVAILABLE: &str = "Email delivery is not configured: set EMAIL_PROVIDER=smtp and ACCOUNT_LINKS_BASE_URL (or OIDC_LOGIN_URL) first";

fn parse_interval(raw: &str) -> Result<Option<i32>, ()> {
    let value = raw
        .trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        .to_ascii_lowercase();
    if value == "never" {
        return Ok(None);
    }
    let (digits, unit) = if let Some(n) = value.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = value.strip_suffix('d') {
        (n, 86400)
    } else {
        return Err(());
    };
    if digits.len() > 4 || digits.starts_with('0') || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    let seconds = digits.parse::<i32>().map_err(|_| ())? * unit;
    (3600..=30 * 86400)
        .contains(&seconds)
        .then_some(Some(seconds))
        .ok_or(())
}

fn label(seconds: Option<i32>) -> String {
    let Some(seconds) = seconds else {
        return "never".into();
    };
    let hours = seconds.div_euclid(3600);
    if hours % 24 == 0 {
        format!("{}d", hours / 24)
    } else {
        format!("{hours}h")
    }
}

type Policy = (Option<i32>, Option<DateTime<Utc>>);
fn document((seconds, updated): Policy) -> Value {
    json!({"magic_link_interval":label(seconds),"updated_at":updated.map(timestamp)})
}

pub(super) async fn get(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    match sqlx::query_as::<_, Policy>(
        "SELECT magic_link_interval_seconds,updated_at FROM auth_policy WHERE id=1",
    )
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(row) => Json(document(row.unwrap_or_default())).into_response(),
        Err(_) => internal(),
    }
}

pub(super) async fn update(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match admin_fields::body(&headers, &bytes) {
        Ok(body) => body,
        Err(r) => return *r,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(body) = body else { return internal() };
    let value = match interval_field(&body) {
        Ok(value) => value,
        Err(issues) => return passkeys::validation(issues),
    };
    let Ok(seconds) = parse_interval(&value) else {
        return problem(StatusCode::UNPROCESSABLE_ENTITY, INVALID);
    };
    if seconds.is_some() && !state.account_mail.supports_confirmation_policy() {
        return problem(StatusCode::CONFLICT, UNAVAILABLE);
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    persist(tx, seconds, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

fn interval_field(value: &Value) -> Result<String, Vec<Value>> {
    let mut fields = admin_fields::Fields {
        body: admin_fields::object(value)?,
        issues: vec![],
    };
    let raw = fields.string("magic_link_interval", Some(16), true);
    if fields.issues.is_empty() {
        Ok(raw.expect("required string"))
    } else {
        Err(fields.issues)
    }
}

async fn persist(
    mut tx: Transaction<'_, Postgres>,
    seconds: Option<i32>,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let previous = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT magic_link_interval_seconds FROM auth_policy WHERE id=1",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let updated = match previous {
        Some(prior) => sqlx::query_scalar::<_, DateTime<Utc>>(
            "UPDATE auth_policy SET updated_at=clock_timestamp(),
                magic_link_interval_seconds=CASE WHEN $2 THEN $1 ELSE magic_link_interval_seconds END
             WHERE id=1 RETURNING updated_at",
        )
        .bind(seconds)
        .bind(seconds != prior)
        .fetch_one(&mut *tx)
        .await?,
        None => sqlx::query_scalar::<_, DateTime<Utc>>(
            "INSERT INTO auth_policy(id,magic_link_interval_seconds,updated_at)
             VALUES (1,$1,clock_timestamp()) RETURNING updated_at",
        )
        .bind(seconds)
        .fetch_one(&mut *tx)
        .await?,
    };
    crate::admin_audit::append(
        &mut tx,
        "settings.update",
        Some(actor),
        ("settings", "auth_policy"),
        json!({"previous":label(previous.flatten()),"magic_link_interval":label(seconds)}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(document((seconds, Some(updated)))).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonicalizes_supported_intervals_and_rejects_invalid_spellings() {
        for (s, expected) in [
            ("  NEVER ", "never"),
            ("720H", "30d"),
            ("24h", "1d"),
            ("1h", "1h"),
        ] {
            assert_eq!(label(parse_interval(s).unwrap()), expected);
        }
        for s in ["", "1", "01d", "+1h", "721h", "9999d", "١h", "1 h", "1w"] {
            assert!(parse_interval(s).is_err(), "{s}");
        }
    }
}
