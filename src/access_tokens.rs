//! Issue a resource server's access token from a checked grant and its authorization snapshot.
use crate::{
    code_exchange::ClaimedGrant,
    grant_sessions::{GrantSessionIssuer, SessionError},
    id_tokens::{AuthorizationClaims, authentication_fields},
};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Effective issuer settings and IAM results for this exchange.
pub struct AccessPolicy<'a> {
    pub admin_emails: &'a [String],
    pub require_verified_admin_email: bool,
    /// A registered resource without an audience override uses its own URL.
    pub resources: &'a BTreeMap<String, Option<String>>,
    pub authorization: Option<&'a AuthorizationClaims>,
}

impl GrantSessionIssuer {
    pub async fn issue_access_token(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        claimed: &ClaimedGrant,
        policy: &AccessPolicy<'_>,
        now: DateTime<Utc>,
        lifetime: TimeDelta,
    ) -> Result<String, SessionError> {
        if lifetime.num_seconds() < 1 {
            return Err(SessionError::InvalidLifetime);
        }
        let expires = now
            .checked_add_signed(lifetime)
            .ok_or(SessionError::InvalidLifetime)?;
        let grant = &claimed.grant;
        let account = sqlx::query(include_str!("access_subject.sql"))
            .bind(grant.user_id)
            .bind(&grant.client_id)
            .bind(now)
            .fetch_one(&mut **tx)
            .await?;
        let audience = match &grant.resource {
            Some(resource) => Some(
                policy
                    .resources
                    .get(resource)
                    .ok_or(SessionError::UnknownResource)?
                    .as_deref()
                    .filter(|a| !a.is_empty())
                    .unwrap_or(resource),
            ),
            None => account.try_get::<Option<&str>, _>("default_audience")?,
        };
        let email = account
            .try_get::<Option<&str>, _>("primary_email")?
            .unwrap_or_default()
            .to_lowercase();
        let admin = account.try_get::<bool, _>("is_admin")?
            || (!email.is_empty()
                && (!policy.require_verified_admin_email
                    || account.try_get::<bool, _>("is_email_verified")?)
                && policy
                    .admin_emails
                    .iter()
                    .any(|allowed| allowed.trim().to_lowercase() == email));
        let scopes = grant
            .scopes
            .split_ascii_whitespace()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(" ");
        let mut doc = json!({"iss":self.issuer(),"sub":grant.user_id.to_string(),"jti":Uuid::new_v4().to_string(),"sid":claimed.session_id.to_string(),
            "iat":now.timestamp(),"exp":expires.timestamp(),"type":"access","client_id":grant.client_id,"scope":scopes,"is_admin":admin,
            "entitlements":account.try_get::<Vec<String>,_>("entitlements")?,"orgs":account.try_get::<Value,_>("memberships")?});
        if let Some(org) = account.try_get::<Option<Value>, _>("primary_org")? {
            doc["org"] = org;
        }
        if let Some(aud) = audience {
            doc["aud"] = json!(aud);
        }
        if let Some(auth) = policy.authorization {
            doc["roles"] = json!(auth.roles.global);
            doc["org_roles"] = json!(auth.roles.organizations);
            if let Some(perms) = &auth.permissions {
                doc["permissions"] = json!(perms.global);
                doc["org_permissions"] = json!(perms.organizations);
            }
        }
        authentication_fields(&mut doc, grant);
        self.sign(&doc)
    }
}
