use super::{Profile, credential, internal, project, revoked, unauthorized, update_input};
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    token_http::{client_ip, header},
};
use axum::{body::to_bytes, extract::Request, http::HeaderMap, response::Response};
use chrono::Utc;
use serde_json::value::RawValue;
use sqlx::{Postgres, Transaction};
use std::net::IpAddr;
use uuid::Uuid;

pub(super) async fn handle(state: &Profile, peer: IpAddr, req: Request) -> Response {
    let (parts, stream) = req.into_parts();
    let Ok(bytes) = to_bytes(stream, usize::MAX).await else {
        return internal();
    };
    let body = match crate::request_json::fields::document(&parts.headers, &bytes) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    apply(state, &parts.headers, peer, body.as_deref())
        .await
        .unwrap_or_else(|_| internal())
}

async fn apply(
    state: &Profile,
    headers: &HeaderMap,
    peer: IpAddr,
    body: Option<&RawValue>,
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
    let Some(body) = body else {
        return Ok(internal());
    };
    match update_input::nullable_string(body, "phone") {
        Err(response) => return Ok(*response),
        Ok(Some(phone)) => {
            let origin = SessionOrigin {
                ip: client_ip(headers, peer, state.proxies),
                user_agent: header(headers, "user-agent"),
            };
            update(
                &mut tx,
                id.user,
                &phone,
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
        "SELECT primary_phone,primary_email,organization_id FROM users WHERE id=$1",
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
    async fn edit_decodes_json_before_requiring_a_session() {
        use axum::{body::Body, extract::ConnectInfo, http::StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/pyloros")
            .unwrap();
        let routes = super::super::routes(pool, false).unwrap();
        for (payload, expected) in [
            (vec![0xff, 0xfe, b'{', 0, b'}', 0], StatusCode::UNAUTHORIZED),
            (vec![0xff], StatusCode::BAD_REQUEST),
            (
                br#"{"phone":"oops"#.to_vec(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let request = axum::http::Request::patch("/api/v1/users/me")
                .header("content-type", "application/json")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8000))))
                .body(Body::from(payload))
                .unwrap();
            assert_eq!(
                routes.clone().oneshot(request).await.unwrap().status(),
                expected
            );
        }
    }

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
