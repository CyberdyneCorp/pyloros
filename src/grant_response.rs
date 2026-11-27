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

impl GrantSessionIssuer {
    /// Build tokens against the same authorization snapshot as the rotation.
    pub async fn issue_refresh_response(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        rotation: crate::oauth_refresh::Rotation,
        calling_client: &str,
        settings: &GrantSettings<'_>,
        now: DateTime<Utc>,
    ) -> Result<TokenResponse, SessionError> {
        let record = crate::grant_sessions::SessionRecord {
            user: rotation.user,
            session: rotation.session,
            client: rotation.client.as_deref(),
            resource: rotation.resource.as_deref(),
            scopes: Some(&rotation.scopes),
            auth_time: rotation.auth_time,
            amr: rotation.amr.as_deref(),
        };
        let mut response = self
            .session_response(tx, record, calling_client, settings, now)
            .await?;
        response.refresh_token = Some(rotation.token);
        Ok(response)
    }

    pub(crate) async fn session_response(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        record: crate::grant_sessions::SessionRecord<'_>,
        calling_client: &str,
        settings: &GrantSettings<'_>,
        now: DateTime<Utc>,
    ) -> Result<TokenResponse, SessionError> {
        let scopes = record.scopes.unwrap_or_default();
        use crate::{
            access_tokens::Subject,
            id_tokens::{AuthorizationClaims, IdentityGrant, authentication_fields},
        };
        use serde_json::json;

        let subject = Subject {
            user: record.user,
            session: record.session,
            client: record.client,
        };
        let (mut claims, default_audience) = self
            .account_claims(
                tx,
                subject,
                settings.admin_emails,
                settings.require_verified_admin_email,
                now,
                settings.access_lifetime,
            )
            .await?;
        claims["scope"] = json!(scopes);
        authentication_fields(&mut claims, record.auth_time, record.amr);
        let auth = if let Some(client) = record.client {
            claims["client_id"] = json!(client);
            let audience = match record.resource {
                Some(resource) => Some(
                    settings
                        .resources
                        .get(resource)
                        .ok_or(SessionError::UnknownResource)?
                        .as_deref()
                        .filter(|aud| !aud.is_empty())
                        .unwrap_or(resource),
                ),
                None => default_audience.as_deref(),
            };
            if let Some(aud) = audience {
                claims["aud"] = json!(aud);
            }
            token_authorization::resolve(tx, record.user, client, audience).await?
        } else {
            token_authorization::profile_roles(tx, record.user)
                .await?
                .map(|roles| AuthorizationClaims {
                    roles,
                    permissions: None,
                })
        };
        authorization_fields(&mut claims, auth.as_ref());
        let access_token = self.sign(&claims)?;
        let id_token = self
            .issue_identity_token(
                tx,
                IdentityGrant {
                    user_id: record.user,
                    client_id: calling_client,
                    scopes,
                    nonce: None,
                    auth_time: record.auth_time,
                    amr: record.amr,
                },
                auth.as_ref(),
                now,
                settings.id_lifetime,
            )
            .await?;
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: settings.access_lifetime.num_seconds(),
            scope: scopes.to_owned(),
            id_token,
            refresh_token: None,
        })
    }
}
