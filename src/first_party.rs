//! Create a login session after the calling workflow has completed authentication.
use crate::{
    access_tokens::Subject,
    grant_response::SessionOrigin,
    grant_sessions::{GrantSessionIssuer, SessionError, SessionRecord},
    token_authorization::profile_roles,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

pub struct AuthenticatedLogin<'a> {
    pub user: Uuid,
    pub authenticated_at: DateTime<Utc>,
    pub methods: &'a [&'a str],
    pub origin: SessionOrigin<'a>,
}

pub struct LoginPolicy<'a> {
    pub access_lifetime: TimeDelta,
    pub admin_emails: &'a [String],
    pub require_verified_admin_email: bool,
}

pub struct SessionPair {
    pub session: Uuid,
    pub access_token: String,
    pub refresh_token: String,
}

impl GrantSessionIssuer {
    /// Publish credentials after the caller commits this session and its audit event.
    pub async fn issue_first_party(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        login: AuthenticatedLogin<'_>,
        policy: &LoginPolicy<'_>,
        now: DateTime<Utc>,
    ) -> Result<SessionPair, SessionError> {
        let session = Uuid::new_v4();
        let methods: Vec<_> = login
            .methods
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let access_token = self
            .first_party_access(
                tx,
                (login.user, session),
                Some(login.authenticated_at),
                &methods,
                policy,
                now,
            )
            .await?;
        let amr = methods.join(" ");
        let record = SessionRecord {
            user: login.user,
            session,
            auth_time: Some(login.authenticated_at),
            amr: Some(&amr),
            client: None,
            scopes: None,
            resource: None,
        };
        let refresh_token = self.store_session(tx, record, login.origin, now).await?;
        Ok(SessionPair {
            session,
            access_token,
            refresh_token,
        })
    }
    pub(crate) async fn first_party_access(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        (user, session): (Uuid, Uuid),
        authenticated_at: Option<DateTime<Utc>>,
        methods: &[&str],
        policy: &LoginPolicy<'_>,
        now: DateTime<Utc>,
    ) -> Result<String, SessionError> {
        let (mut claims, _) = self
            .account_claims(
                tx,
                Subject {
                    user,
                    session,
                    client: None,
                },
                policy.admin_emails,
                policy.require_verified_admin_email,
                now,
                policy.access_lifetime,
            )
            .await?;
        if let Some(at) = authenticated_at {
            claims["auth_time"] = json!(at.timestamp());
            claims["amr"] = json!(methods);
        }
        if let Some(roles) = profile_roles(tx, user).await? {
            claims["roles"] = json!(roles.global);
            claims["org_roles"] = json!(roles.organizations);
        }
        self.sign(&claims)
    }
}
