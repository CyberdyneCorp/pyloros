//! Submit a signed browser consent decision against the registered callback.
use crate::{
    browser_client::{self, ClientError},
    browser_http, browser_prompt,
    login_http::problem,
    token_runtime::Runtime,
};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) const PATH: &str = "/api/v1/auth/oauth2/authorize/consent";

#[derive(Deserialize)]
pub(crate) struct Ticket {
    #[serde(rename = "type")]
    pub kind: String,
    sub: Uuid,
    client_id: String,
    resource: String,
    scope: String,
    authz: String,
}

pub(crate) fn routes(rt: Option<Arc<Runtime>>) -> Router {
    Router::new().route(PATH, any(submit)).with_state(rt)
}

fn bad(message: &str) -> Response {
    problem(StatusCode::BAD_REQUEST, message)
}
fn unavailable() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Authorization service unavailable",
    )
}

async fn submit(State(rt): State<Option<Arc<Runtime>>>, req: Request) -> Response {
    if req.method() != Method::POST {
        let mut res = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        res.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        return res;
    }
    let headers = req.headers().clone();
    let fields = match crate::token_http::fields(req).await {
        Ok(f) => f,
        Err(res) => return *res,
    };
    let value = |key: &str| {
        fields
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    };
    let (Some(raw), Some(decision)) = (value("ticket"), value("decision")) else {
        let issues: Vec<_>=["ticket","decision"].into_iter().filter(|k|value(k).is_none()).map(|key|json!({"loc":["body",key],"type":"missing","msg":"Field required","input":null})).collect();
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"detail":issues})),
        )
            .into_response();
    };
    let Some(rt) = rt else {
        return problem(StatusCode::NOT_FOUND, "OIDC disabled");
    };
    let Ok(mut tx) = rt.pool.begin().await else {
        return unavailable();
    };
    let session = match rt
        .verifier
        .browser_session(&headers, &mut tx, rt.enforce_revocation)
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return problem(StatusCode::UNAUTHORIZED, "Not authenticated"),
        Err(_) => return unavailable(),
    };
    let Some(ticket) = rt.verifier.consent_ticket(raw) else {
        return bad("invalid or expired consent ticket");
    };
    if ticket.sub != session.user {
        return bad("consent ticket belongs to another user");
    }
    resolve(tx, ticket, decision).await
}

async fn resolve(mut tx: Transaction<'_, Postgres>, ticket: Ticket, decision: &str) -> Response {
    let query: Vec<_> = url::form_urlencoded::parse(ticket.authz.as_bytes())
        .filter(|(_, value)| !value.is_empty())
        .collect();
    let first = |key: &str| {
        query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_ref())
    };
    let callback = first("redirect_uri");
    match browser_client::resolve(&mut tx, Some(&ticket.client_id), callback).await {
        Ok(client) if !client.trusted => {}
        Err(ClientError::Database(_)) => return unavailable(),
        Err(ClientError::Callback) => return bad("redirect_uri not registered for this client"),
        _ => return bad("client is no longer available"),
    }
    let target = match decision {
        "deny" => {
            let mut params = url::form_urlencoded::Serializer::new(String::new());
            params.append_pair("error", "access_denied");
            if let Some(state) = first("state") {
                params.append_pair("state", state);
            }
            format!(
                "{}?{}",
                callback.unwrap_or_default(),
                browser_prompt::encode_query(params)
            )
        }
        "approve" => format!("{}?{}", browser_http::PATH, ticket.authz),
        _ => return bad("decision must be approve or deny"),
    };
    let Ok(location) = browser_http::location_header(&target) else {
        return bad("Invalid redirect URL");
    };
    if decision == "approve"
        && (grant(&mut tx, &ticket).await.is_err() || tx.commit().await.is_err())
    {
        return unavailable();
    }
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

async fn grant(tx: &mut Transaction<'_, Postgres>, ticket: &Ticket) -> Result<(), sqlx::Error> {
    let mut scopes = ticket.scope.split_whitespace().collect::<Vec<_>>();
    scopes.sort_unstable();
    scopes.dedup();
    sqlx::query("INSERT INTO oauth_consents(id,user_id,client_id,resource,scopes) VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (user_id,client_id,resource) DO UPDATE SET scopes=(
            SELECT coalesce(string_agg(DISTINCT scope,' ' ORDER BY scope),'')
            FROM unnest(string_to_array(oauth_consents.scopes || ' ' || EXCLUDED.scopes,' ')) AS scope WHERE scope <> ''
        ), updated_at=now()
        WHERE NOT string_to_array(EXCLUDED.scopes,' ') <@ string_to_array(oauth_consents.scopes,' ')")
        .bind(Uuid::new_v4()).bind(ticket.sub).bind(&ticket.client_id).bind(&ticket.resource).bind(scopes.join(" ")).execute(&mut **tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn repeated_approval_preserves_prior_scopes_and_timestamps() {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_consents(id uuid, user_id uuid, client_id text, resource text, scopes text, updated_at timestamptz default now(), UNIQUE(user_id,client_id,resource))").execute(&mut *tx).await.unwrap();
        let mut ticket = Ticket {
            kind: "consent".into(),
            sub: Uuid::new_v4(),
            client_id: "app".into(),
            resource: String::new(),
            scope: "roles".into(),
            authz: String::new(),
        };
        grant(&mut tx, &ticket).await.unwrap();
        ticket.scope = "openid".into();
        grant(&mut tx, &ticket).await.unwrap();
        sqlx::query("UPDATE oauth_consents SET updated_at='2000-01-01 UTC'")
            .execute(&mut *tx)
            .await
            .unwrap();
        grant(&mut tx, &ticket).await.unwrap();
        let row: (String, bool) =
            sqlx::query_as("SELECT scopes,updated_at='2000-01-01 UTC' FROM oauth_consents")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(row, ("openid roles".into(), true));
        tx.rollback().await.unwrap();
    }
}
