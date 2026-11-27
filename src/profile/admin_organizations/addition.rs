//! Add an explicit membership and record the operator action in one transaction.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::fields};
use serde::Serialize;
use serde_json::value::RawValue;

pub(in crate::profile) async fn add(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match fields::document(&headers, &bytes) {
        Ok(body) => body,
        Err(error) => return *error,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Some(body) = body else { return internal() };
    let (user, org) = match input(&path, &body) {
        Ok(ids) => ids,
        Err(error) => return *error,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    write(tx, user, org, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

fn input(path: &str, body: &RawValue) -> Result<(Uuid, Uuid), Box<Response>> {
    let user = crate::query::path_uuid(path, "user_id");
    let (value, original) = fields::validation_input(body, "organization_id")?;
    let org = admin_fields::object_field(&value).and_then(|object| match object.get("organization_id") {
        None => Err(json!({"type":"missing","loc":["body","organization_id"],"msg":"Field required"})),
        Some(Value::String(s)) => crate::query::uuid_field(s, "body", "organization_id"),
        Some(_) => Err(json!({"type":"uuid_type","loc":["body","organization_id"],"msg":"UUID input should be a string, bytes or UUID object"})),
    });
    if let (Ok(user), Ok(org)) = (&user, &org) {
        return Ok((*user, *org));
    }
    #[derive(Serialize)]
    struct Errors<'a> {
        detail: Vec<fields::FieldIssue<'a>>,
    }
    let path = serde_json::value::to_raw_value(path).expect("string is JSON");
    let mut detail = Vec::new();
    if let Err(issue) = user {
        detail.push(fields::field_issue(issue, &path));
    }
    if let Err(issue) = org {
        if !fields::finite_error_input(original) {
            return Err(Box::new(internal()));
        }
        detail.push(fields::field_issue(issue, original));
    }
    Err(Box::new(
        (StatusCode::UNPROCESSABLE_ENTITY, Json(Errors { detail })).into_response(),
    ))
}

async fn write(
    mut tx: Transaction<'_, Postgres>,
    user: Uuid,
    org: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    if !user_exists(&mut tx, user).await? {
        return Ok(problem(StatusCode::NOT_FOUND, &format!("user {user}")));
    }
    let active: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM organizations WHERE id=$1 AND is_active)")
            .bind(org)
            .fetch_one(&mut *tx)
            .await?;
    if !active {
        return Ok(problem(StatusCode::NOT_FOUND, &org.to_string()));
    }
    sqlx::query("INSERT INTO user_organizations(user_id,organization_id)
                 SELECT $1,$2 WHERE NOT EXISTS(SELECT FROM user_organizations WHERE user_id=$1 AND organization_id=$2)")
        .bind(user).bind(org).execute(&mut *tx).await?;
    crate::admin_audit::append(
        &mut tx,
        "user.add_organization",
        Some(actor),
        ("user", &user.to_string()),
        json!({"organization_id":org}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(Value::Null)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_preserves_large_integers_and_distinguishes_literal_overflow() {
        for (json, expected) in [
            (r#"[{"key":"1e999"},123456789012345678901234567890]"#, true),
            (r#"{"ignored":[1e999]}"#, false),
        ] {
            assert_eq!(
                fields::finite_error_input(serde_json::from_str(json).unwrap()),
                expected
            );
        }
    }
}
