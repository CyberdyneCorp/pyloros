use super::{Profile, credential, internal, project, revoked, unauthorized};
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    token_http::{client_ip, header},
};
use axum::{
    Json,
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use std::net::IpAddr;
use uuid::Uuid;

fn validation(issue: Value) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail":[issue]})),
    )
        .into_response()
}

fn phone(body: &Value) -> Result<Option<&str>, Value> {
    if body.is_null() {
        return Err(json!({"loc":["body"],"type":"missing","msg":"Field required","input":null}));
    }
    if !body.is_object() {
        return Err(
            json!({"loc":["body"],"type":"model_attributes_type","msg":"Input should be a valid dictionary or object to extract fields from","input":body}),
        );
    }
    match &body["phone"] {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value)),
        other => Err(
            json!({"loc":["body","phone"],"type":"string_type","msg":"Input should be a valid string","input":other}),
        ),
    }
}

pub(super) async fn handle(state: &Profile, peer: IpAddr, req: Request) -> Response {
    let (parts, stream) = req.into_parts();
    let Ok(bytes) = to_bytes(stream, 2 * 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let body = match crate::request_json::parse_body(&parts.headers, &bytes) {
        Ok(value) => value,
        Err(issue) => return validation(issue),
    };
    apply(state, &parts.headers, peer, &body)
        .await
        .unwrap_or_else(|_| internal())
}

async fn apply(
    state: &Profile,
    headers: &HeaderMap,
    peer: IpAddr,
    body: &Value,
) -> Result<Response, sqlx::Error> {
    let Some(id) = credential(headers).and_then(|raw| state.verify.as_ref()?.read(raw)) else {
        return Ok(unauthorized());
    };
    if id.client_bound {
        return Ok(unauthorized());
    }
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, &id).await? {
        return Ok(unauthorized());
    }
    match phone(body) {
        Err(issue) => return Ok(validation(issue)),
        Ok(Some(phone)) => {
            let origin = SessionOrigin {
                ip: client_ip(headers, peer, state.proxies),
                user_agent: header(headers, "user-agent"),
            };
            update(
                &mut tx,
                id.user,
                phone,
                origin,
                header(headers, "x-request-id"),
            )
            .await?;
        }
        Ok(None) => {}
    }
    let result = project(state, &mut tx, id.user, false).await?;
    tx.commit().await?;
    Ok(result)
}

async fn update(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    phone: &str,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query_as::<_, (Option<String>, Option<String>, Option<Uuid>)>(
        "SELECT primary_phone,primary_email,organization_id FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((previous, email, organization)) = row else {
        return Ok(());
    };
    let next = (!phone.is_empty()).then_some(phone);
    sqlx::query(
        "UPDATE users SET primary_phone=$2,is_phone_verified=false,updated_at=now()
        WHERE id=$1 AND (primary_phone IS DISTINCT FROM $2 OR is_phone_verified)",
    )
    .bind(user)
    .bind(next)
    .execute(&mut **tx)
    .await?;
    if previous.as_deref() != next {
        write_activity(
            &mut **tx,
            AuditActivity::PhoneEdit,
            AuditSubject {
                user: Some(user),
                email,
                organization,
            },
            origin,
            request_id,
            Utc::now(),
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Acquire, PgPool};

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn failed_audit_rolls_back_phone_and_verification() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut outer = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users (id uuid, primary_phone text, primary_email text,
              organization_id uuid, is_phone_verified boolean, updated_at timestamptz);
              CREATE TEMP TABLE auth_events (activity text CHECK (activity <> 'subject_rectification'));")
            .execute(&mut *outer).await.unwrap();
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id,primary_phone,is_phone_verified) VALUES ($1,'123',true)",
        )
        .bind(id)
        .execute(&mut *outer)
        .await
        .unwrap();
        let mut attempt = outer.begin().await.unwrap();
        let origin = SessionOrigin {
            ip: None,
            user_agent: None,
        };
        let err = update(&mut attempt, id, "456", origin, None)
            .await
            .unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
        attempt.rollback().await.unwrap();
        let row = sqlx::query_as::<_, (String, bool)>(
            "SELECT primary_phone,is_phone_verified FROM users WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&mut *outer)
        .await
        .unwrap();
        assert_eq!(row, ("123".into(), true));
    }
}
