//! Resolve active user and service tokens for an authenticated resource server.
use super::service_identity::{caller, registration};
use super::*;
use crate::{token_authorization, token_http, token_revocation::VerifiedToken};
use axum::http::{HeaderValue, Method};
use chrono::DateTime;
use serde_json::Value;
use sqlx::Row;
use std::collections::BTreeSet;

pub(super) async fn handle(State(login): State<Option<Arc<Login>>>, req: Request) -> Response {
    if req.method() != Method::POST {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(h::ALLOW, HeaderValue::from_static("POST"));
        return r;
    }
    let (login, _) = match caller(login, req.headers()).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let fields = match token_http::fields(req).await {
        Ok(fields) => fields,
        Err(response) => return *response,
    };
    let Some((_, token)) = fields
        .iter()
        .rev()
        .find(|(k, _)| k == "token")
        .filter(|(_, v)| !v.is_empty())
    else {
        return (StatusCode::UNPROCESSABLE_ENTITY,Json(json!({"detail":[{"type":"missing","loc":["body","token"],"msg":"Field required","input":null}]}))).into_response();
    };
    match login.introspect(token).await {
        Ok(result) => Json(result.unwrap_or_else(|| json!({"active":false}))).into_response(),
        Err(_) => internal_error(),
    }
}

impl Login {
    async fn introspect(&self, token: &str) -> Result<Option<Value>, sqlx::Error> {
        let Ok(claims) = self.verifier.verified_claims(token) else {
            return Ok(None);
        };
        match VerifiedToken::from_verified_claims(&claims) {
            Ok(VerifiedToken::Service {
                id,
                client,
                expires,
            }) => {
                if registration(&self.pool, &client, id, true).await?.is_err() {
                    return Ok(None);
                }
                let mut body = json!({"active":true,"sub":format!("client:{client}"),"client_id":client,"token_type":"service","exp":expires.timestamp(),"iat":claims["iat"],"scope":scope(&claims).unwrap_or_default()});
                if let Some(aud) = claims["aud"].as_str() {
                    body["aud"] = json!(aud)
                }
                Ok(Some(body))
            }
            Ok(VerifiedToken::Access {
                id,
                user,
                expires,
                client,
            }) => {
                self.inspect_user(&claims, id, user, expires, client.as_deref())
                    .await
            }
            _ => Ok(None),
        }
    }
    async fn inspect_user(
        &self,
        claims: &Value,
        id: Uuid,
        user: Uuid,
        expires: DateTime<Utc>,
        client: Option<&str>,
    ) -> Result<Option<Value>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let session = claims["sid"].as_str().and_then(|s| s.parse::<Uuid>().ok());
        let revoked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti=$1)
                       OR EXISTS(SELECT 1 FROM sessions WHERE id=$2 AND revoked_at IS NOT NULL)",
        )
        .bind(id)
        .bind(session)
        .fetch_one(&mut *tx)
        .await?;
        if revoked {
            return Ok(None);
        }
        let row = sqlx::query(include_str!("../access_subject.sql"))
            .bind(user)
            .bind(client)
            .bind(Utc::now())
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let email = row.try_get::<Option<&str>, _>("primary_email")?;
        let admin = crate::config::effective_admin(
            row.try_get("is_admin")?,
            email,
            row.try_get("is_email_verified")?,
            self.production,
            &self.admins,
        );
        let mut body = json!({"active":true,"sub":user,"exp":expires.timestamp(),"token_type":"user","is_admin":admin,
            "entitlements":row.try_get::<Vec<String>,_>("entitlements")?,"orgs":row.try_get::<Value,_>("memberships")?});
        if let Some(email) = email {
            body["username"] = json!(email)
        }
        if let Some(org) = row.try_get::<Option<Value>, _>("primary_org")? {
            body["org"] = org
        }
        let audience = claims["aud"].as_str();
        if let Some(aud) = audience {
            body["aud"] = json!(aud)
        }
        if let Some(scope) = scope(claims) {
            body["scope"] = json!(scope)
        }
        if let Some(client) = client {
            body["client_id"] = json!(client);
            let auth = token_authorization::resolve_with(
                &self.issuer.blockchain,
                &mut tx,
                user,
                client,
                audience,
            )
            .await?;
            crate::access_tokens::authorization_fields(&mut body, auth.as_ref());
        } else if let Some(roles) =
            token_authorization::profile_roles(&self.issuer.blockchain, &mut tx, user).await?
        {
            body["roles"] = json!(roles.global);
            body["org_roles"] = json!(roles.organizations);
        }
        if let Some(time) = claims["auth_time"].as_i64() {
            body["auth_time"] = json!(time);
            let methods: BTreeSet<_> = claims["amr"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            body["amr"] = json!(methods);
        }
        tx.commit().await?;
        Ok(Some(body))
    }
}

fn scope(claims: &Value) -> Option<String> {
    Some(
        claims["scope"]
            .as_str()?
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(" "),
    )
}
