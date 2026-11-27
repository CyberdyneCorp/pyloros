//! Explicit membership and primary organization assignment.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::fields};
use serde::Serialize;
use serde_json::value::RawValue;

pub(in crate::profile) async fn assign(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
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
    let primary = method == Method::PUT;
    let (user, org) = match input(&path, &body, primary) {
        Ok(ids) => ids,
        Err(error) => return *error,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    write(tx, user, org, primary, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

fn input(
    path: &str,
    body: &RawValue,
    primary: bool,
) -> Result<(Uuid, Option<Uuid>), Box<Response>> {
    let user = crate::query::path_uuid(path, "user_id");
    let (value, original) = fields::validation_input(body, "organization_id")?;
    let org = admin_fields::object_field(&value).and_then(|object| match object.get("organization_id") {
        None if primary => Ok(None),
        Some(Value::Null) if primary && original.get() == "null" => Ok(None),
        None => Err(json!({"type":"missing","loc":["body","organization_id"],"msg":"Field required"})),
        Some(Value::String(s)) => crate::query::uuid_field(s, "body", "organization_id").map(Some),
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
    org: Option<Uuid>,
    primary: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let user_record: Option<(Option<Uuid>, String)> =
        sqlx::query_as("SELECT organization_id,extra_metadata::text FROM users WHERE id=$1")
            .bind(user)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((previous, user_metadata)) = user_record else {
        return Ok(problem(StatusCode::NOT_FOUND, &format!("user {user}")));
    };
    let canonical = metadata::normalized_storage(&user_metadata)?;
    if let Some(org) = org
        && !ensure_membership(&mut tx, user, org).await?
    {
        return Ok(problem(StatusCode::NOT_FOUND, &org.to_string()));
    }
    if primary && (previous != org || canonical.is_some()) {
        sqlx::query("UPDATE users SET organization_id=CASE WHEN $2 THEN $3 ELSE organization_id END,
                    extra_metadata=COALESCE($4::text::jsonb,extra_metadata), updated_at=now() WHERE id=$1")
            .bind(user).bind(previous != org).bind(org).bind(canonical).execute(&mut *tx).await?;
    }
    crate::admin_audit::append(
        &mut tx,
        if primary {
            "user.set_organization"
        } else {
            "user.add_organization"
        },
        Some(actor),
        ("user", &user.to_string()),
        json!({"organization_id":org}),
        origin,
    )
    .await?;
    tx.commit().await?;
    if primary {
        Ok((
            StatusCode::NO_CONTENT,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
        )
            .into_response())
    } else {
        Ok((StatusCode::CREATED, Json(Value::Null)).into_response())
    }
}

async fn ensure_membership(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    org: Uuid,
) -> Result<bool, sqlx::Error> {
    let record: Option<(bool, String)> =
        sqlx::query_as("SELECT is_active,extra_metadata::text FROM organizations WHERE id=$1")
            .bind(org)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((active, metadata)) = record else {
        return Ok(false);
    };
    metadata::normalized_storage(&metadata)?;
    if !active {
        return Ok(false);
    }
    sqlx::query("INSERT INTO user_organizations(user_id,organization_id)
                 SELECT $1,$2 WHERE NOT EXISTS(SELECT FROM user_organizations WHERE user_id=$1 AND organization_id=$2)")
        .bind(user).bind(org).execute(&mut **tx).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_null_and_omission_can_clear_the_primary_organization() {
        let user = Uuid::new_v4().to_string();
        for document in ["{}", r#"{"organization_id":null}"#] {
            let raw = serde_json::from_str(document).unwrap();
            assert_eq!(input(&user, raw, true).unwrap().1, None);
            assert!(input(&user, raw, false).is_err());
        }
        let overflow = serde_json::from_str(r#"{"organization_id":1e999}"#).unwrap();
        assert_eq!(
            input(&user, overflow, true).unwrap_err().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

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
