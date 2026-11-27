//! Bearer authentication and the live registration of a service client.
use super::*;
use crate::{csrf::bearer, token_revocation::VerifiedToken};
use axum::http::{HeaderMap, HeaderValue, Method};
use chrono::SecondsFormat;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Serialize)]
pub(super) struct Identity {
    client_id: String,
    name: String,
    scopes: BTreeSet<String>,
    audiences: Option<BTreeSet<String>>,
    expires_at: String,
}

pub(super) async fn handle(State(login): State<Option<Arc<Login>>>, req: Request) -> Response {
    if req.method() != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    match caller(login, req.headers()).await {
        Ok((_, identity)) => Json(identity).into_response(),
        Err(response) => *response,
    }
}

pub(crate) fn unauthorized(reason: &str) -> Box<Response> {
    let mut response = problem(StatusCode::UNAUTHORIZED, reason);
    response
        .headers_mut()
        .insert(h::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    Box::new(response)
}

pub(crate) struct Registration {
    pub(crate) allowed_scopes: String,
    name: String,
    audiences: Option<BTreeSet<String>>,
}

pub(crate) async fn registration(
    pool: &PgPool,
    client: &str,
    id: Uuid,
    enforce: bool,
) -> Result<Result<Registration, &'static str>, sqlx::Error> {
    type StoredAudiences = sqlx::types::Json<Option<BTreeSet<String>>>;
    let row = sqlx::query_as::<_, (String, Option<StoredAudiences>, String, bool)>(
        "SELECT name,allowed_audiences,allowed_scopes,$3 AND EXISTS(SELECT 1 FROM revoked_tokens WHERE jti=$2)
           FROM oauth_clients WHERE client_id=$1 AND active",
    )
    .bind(client)
    .bind(id)
    .bind(enforce)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        None => Err("Client disabled or unknown"),
        Some((_, _, _, true)) => Err("Invalid service token"),
        Some((name, list, allowed_scopes, false)) => Ok(Registration {
            name,
            allowed_scopes,
            audiences: list.and_then(|list| list.0),
        }),
    })
}

pub(super) async fn caller(
    login: Option<Arc<Login>>,
    headers: &HeaderMap,
) -> Result<(Arc<Login>, Identity), Box<Response>> {
    let raw = bearer(headers).ok_or_else(|| unauthorized("Not authenticated"))?;
    let login = login.ok_or_else(|| {
        Box::new(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Login signing unavailable",
        ))
    })?;
    let invalid = || unauthorized("Invalid service token");
    let claims = login.verifier.verified_claims(raw).map_err(|_| invalid())?;
    let Ok(VerifiedToken::Service {
        client,
        id,
        expires,
    }) = VerifiedToken::from_verified_claims(&claims)
    else {
        return Err(invalid());
    };
    let record = registration(&login.pool, &client, id, login.enforce_revocation)
        .await
        .map_err(|_| Box::new(internal_error()))?
        .map_err(unauthorized)?;
    let scopes = claims["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    Ok((
        login,
        Identity {
            client_id: client,
            name: record.name,
            audiences: record.audiences,
            scopes,
            expires_at: expires.to_rfc3339_opts(SecondsFormat::Secs, true),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_disabled_client_is_rejected_even_when_denylist_enforcement_is_off() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE oauth_clients(client_id text, name text, active boolean, allowed_audiences jsonb, allowed_scopes text);
            CREATE TEMP TABLE revoked_tokens(jti uuid);
            INSERT INTO oauth_clients VALUES ('svc','Service',true,'[\"b\",\"a\",\"a\"]','users:provision');")
            .execute(&pool).await.unwrap();
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO revoked_tokens VALUES ($1)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let client = registration(&pool, "svc", id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            client.audiences.unwrap().into_iter().collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(matches!(
            registration(&pool, "svc", id, true).await.unwrap(),
            Err("Invalid service token")
        ));
        sqlx::query("UPDATE oauth_clients SET active=false")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            registration(&pool, "svc", id, false).await.unwrap(),
            Err("Client disabled or unknown")
        ));
    }

    #[tokio::test]
    async fn a_cookie_alone_cannot_authenticate_a_service() {
        let req = Request::get("/api/v1/clients/me")
            .header(h::COOKIE, "access_token=session")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = handle(State(None), req).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[h::WWW_AUTHENTICATE], "Bearer");
    }
}
