//! Compose a response for a redeemed code using the grant transaction.
use crate::{
    access_tokens::{AccessPolicy, authorization_fields},
    code_exchange::ClaimedGrant,
    grant_sessions::{GrantSessionIssuer, SessionError},
    token_authorization,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
use sqlx::{Postgres, Transaction};
use std::{collections::BTreeMap, net::IpAddr};

pub struct GrantSettings<'a> {
    pub access_lifetime: TimeDelta,
    pub id_lifetime: TimeDelta,
    pub admin_emails: &'a [String],
    pub require_verified_admin_email: bool,
    pub resources: &'a BTreeMap<String, Option<String>>,
}

#[derive(Clone, Copy)]
pub struct SessionOrigin<'a> {
    pub user_agent: Option<&'a str>,
    pub ip: Option<IpAddr>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl GrantSessionIssuer {
    /// PostgreSQL IAM path. Commit the surrounding transaction before sending the response.
    pub async fn issue_grant_response(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        claimed: &ClaimedGrant,
        settings: &GrantSettings<'_>,
        origin: SessionOrigin<'_>,
        now: DateTime<Utc>,
    ) -> Result<TokenResponse, SessionError> {
        let policy = AccessPolicy {
            admin_emails: settings.admin_emails,
            require_verified_admin_email: settings.require_verified_admin_email,
            resources: settings.resources,
            authorization: None,
        };
        let mut claims = self
            .access_claims(tx, claimed, &policy, now, settings.access_lifetime)
            .await?;
        let auth = token_authorization::resolve(
            tx,
            claimed.grant.user_id,
            &claimed.grant.client_id,
            claims["aud"].as_str(),
        )
        .await?;
        authorization_fields(&mut claims, auth.as_ref());
        let access_token = self.sign(&claims)?;
        let id_token = self
            .issue_id_token(tx, claimed, auth.as_ref(), now, settings.id_lifetime)
            .await?;
        let refresh_token = self
            .create(tx, claimed, now, origin.user_agent, origin.ip)
            .await?;
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: settings.access_lifetime.num_seconds(),
            scope: claims["scope"].as_str().unwrap_or_default().to_owned(),
            id_token,
            refresh_token,
        })
    }
}
