//! Scope-dependent identity claims for a verified user grant.
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    code_exchange::ClaimedGrant,
    grant_sessions::{GrantSessionIssuer, SessionError},
};

#[derive(Default)]
pub struct Assignments {
    pub global: Vec<String>,
    pub organizations: BTreeMap<String, Vec<String>>,
}

pub struct AuthorizationClaims {
    pub roles: Assignments,
    /// Permissions previously resolved for this grant's effective audience.
    pub permissions: Option<Assignments>,
}

fn client_roles(roles: &[String], prefix: &str) -> Vec<String> {
    let mut result: Vec<_> = roles
        .iter()
        .filter_map(|r| r.strip_prefix(prefix).map(str::to_owned))
        .collect();
    result.sort();
    result
}

fn authorization_fields(doc: &mut Value, client: &str, auth: &AuthorizationClaims) {
    let prefix = format!("{client}:");
    doc["roles"] = json!(client_roles(&auth.roles.global, &prefix));
    let mut by_org = BTreeMap::new();
    for (org, roles) in &auth.roles.organizations {
        let selected = client_roles(roles, &prefix);
        if !selected.is_empty() {
            by_org.insert(org, selected);
        }
    }
    doc["org_roles"] = json!(by_org);
    if let Some(perms) = &auth.permissions {
        doc["permissions"] = json!(perms.global);
        doc["org_permissions"] = json!(perms.organizations);
    }
}

fn has_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::Number(v) => v.as_f64() != Some(0.0),
        Value::String(v) => !v.is_empty(),
        Value::Array(v) => !v.is_empty(),
        Value::Object(v) => !v.is_empty(),
    }
}

pub(crate) fn profile_fields(doc: &mut Value, metadata: &Value) {
    for (claim, fallback) in [("name", "full_name"), ("picture", "avatar_url")] {
        if let Some(value) = [claim, fallback]
            .into_iter()
            .filter_map(|k| metadata.get(k))
            .find(|v| has_value(v))
        {
            doc[claim] = value.clone();
        }
    }
}

pub(crate) fn authentication_fields(doc: &mut Value, grant: &crate::authorization_codes::Grant) {
    if let Some(time) = grant.auth_time {
        doc["auth_time"] = json!(time.timestamp());
        doc["amr"] = json!(
            grant
                .amr
                .as_deref()
                .unwrap_or_default()
                .split_ascii_whitespace()
                .collect::<BTreeSet<_>>()
        );
    }
}

impl GrantSessionIssuer {
    pub async fn issue_id_token(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        claimed: &ClaimedGrant,
        auth: Option<&AuthorizationClaims>,
        now: DateTime<Utc>,
        lifetime: TimeDelta,
    ) -> Result<Option<String>, SessionError> {
        let grant = &claimed.grant;
        let scopes: BTreeSet<_> = grant.scopes.split_ascii_whitespace().collect();
        if !scopes.contains("openid") {
            return Ok(None);
        }
        if lifetime.num_seconds() < 1 {
            return Err(SessionError::InvalidLifetime);
        }
        let exp = now
            .checked_add_signed(lifetime)
            .ok_or(SessionError::InvalidLifetime)?;
        let mut doc = json!({"iss":self.issuer(),"sub":grant.user_id.to_string(),"aud":grant.client_id,
            "iat":now.timestamp(),"exp":exp.timestamp()});
        if let Some(nonce) = grant.nonce.as_deref().filter(|n| !n.is_empty()) {
            doc["nonce"] = json!(nonce);
        }
        authentication_fields(&mut doc, grant);
        if scopes.contains("email") || scopes.contains("profile") {
            let row = sqlx::query(
                "SELECT primary_email, is_email_verified, extra_metadata FROM users WHERE id=$1",
            )
            .bind(grant.user_id)
            .fetch_one(&mut **tx)
            .await?;
            if scopes.contains("email")
                && let Some(email) = row
                    .try_get::<Option<&str>, _>("primary_email")?
                    .filter(|s| !s.is_empty())
            {
                doc["email"] = json!(email);
                doc["email_verified"] = json!(row.try_get::<bool, _>("is_email_verified")?);
            }
            if scopes.contains("profile") {
                let metadata: Value = row.try_get("extra_metadata")?;
                profile_fields(&mut doc, &metadata);
            }
        }
        if scopes.contains("roles")
            && let Some(auth) = auth
        {
            authorization_fields(&mut doc, &grant.client_id, auth);
        }
        Ok(Some(self.sign(&doc)?))
    }
}
