//! Client authentication, token issuance and audit for a refresh exchange.
use super::{GrantSettings, Runtime, SessionOrigin};
use crate::{
    browser_client::grant::ResourceScopes,
    client_auth,
    code_decision::{CodeDecision, OAuthError},
    grant_audit::{GrantEvent, write_event},
    grant_sessions::SessionError,
    oauth_refresh::{RefreshRequest, Refused, Rotation},
};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};

pub(super) struct Request<'a> {
    pub client: &'a str,
    pub secret: Option<&'a str>,
    pub token: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub resources: &'a [String],
    pub registry: &'a ResourceScopes,
}

fn refusal(reason: &'static str, description: &'static str) -> Refused {
    Refused {
        user: None,
        reason,
        description,
    }
}

async fn authenticate_and_rotate(
    rt: &Runtime,
    tx: &mut Transaction<'_, Postgres>,
    req: &Request<'_>,
    now: DateTime<Utc>,
) -> Result<Result<Rotation, Refused>, SessionError> {
    if req.client.is_empty() {
        return Ok(Err(refusal("invalid_client", "missing client_id")));
    }
    let row = sqlx::query("SELECT client_type,grant_types,allowed_scopes,secret_hash,
        CASE WHEN previous_secret_expires_at > $2 THEN previous_secret_hash END AS grace_hash
        FROM oauth_clients WHERE active AND client_id=$1 AND client_type IN ('public','confidential') FOR SHARE")
        .bind(req.client).bind(now).fetch_optional(&mut **tx).await?;
    let Some(row) = row else {
        return Ok(Err(refusal("invalid_client", "unknown client")));
    };
    if !client_auth::authenticates(&row, req.secret).await? {
        return Ok(Err(refusal("invalid_client", "bad client secret")));
    }
    if !row
        .try_get::<&str, _>("grant_types")?
        .split_whitespace()
        .any(|g| g == "refresh_token")
    {
        return Ok(Err(refusal(
            "unauthorized_client",
            "client may not use the refresh_token grant",
        )));
    }
    let Some(token) = req.token else {
        return Ok(Err(refusal("invalid_grant", "missing refresh_token")));
    };
    rt.signer
        .rotate_oauth_refresh(
            tx,
            &rt.refresh_verifier,
            &RefreshRequest {
                token,
                client: req.client,
                client_scopes: row.try_get("allowed_scopes")?,
                requested_scopes: req.scope,
                requested_resources: req.resources,
                registry: req.registry,
            },
            now,
        )
        .await
}

pub(super) async fn exchange(
    rt: &Runtime,
    req: Request<'_>,
    settings: &GrantSettings<'_>,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<CodeDecision, SessionError> {
    let mut tx = rt.pool.begin().await?;
    let rotation = match authenticate_and_rotate(rt, &mut tx, &req, now).await? {
        Ok(rotation) => rotation,
        Err(failure) => {
            tx.commit().await?;
            let error = match failure.reason {
                "invalid_client" | "unauthorized_client" | "invalid_target" => failure.reason,
                _ => "invalid_grant",
            };
            let event = GrantEvent {
                user: failure.user,
                email: None,
                organization: None,
                client: req.client,
                reason: Some(failure.reason),
                details: json!({"grant_type":"refresh_token"}),
            };
            if write_event(&rt.pool, event, origin, request_id, now)
                .await
                .is_err()
            {
                eprintln!(
                    "could not persist refresh grant refusal ({})",
                    failure.reason
                );
            }
            return Ok(CodeDecision::Refused(OAuthError {
                error,
                error_description: failure.description,
            }));
        }
    };
    let user = rotation.user;
    let session = rotation.session;
    let response = rt
        .signer
        .issue_refresh_response(&mut tx, rotation, req.client, settings, now)
        .await?;
    let event = GrantEvent::issued(
        &mut tx,
        user,
        req.client,
        "refresh_token",
        session,
        &response.scope,
    )
    .await?;
    write_event(&mut *tx, event, origin, request_id, now).await?;
    tx.commit().await?;
    Ok(CodeDecision::Issued(response))
}
