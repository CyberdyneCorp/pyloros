//! Store the audit decision alongside the session created by a code exchange.
use crate::{
    code_exchange::ClaimedGrant,
    grant_response::{GrantSettings, SessionOrigin, TokenResponse},
    grant_sessions::{GrantSessionIssuer, SessionError},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

fn valid_request_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b))
}

fn grant_details(session: Uuid, scopes: &str) -> Value {
    let bounded: Vec<String> = scopes
        .split_ascii_whitespace()
        .map(|scope| scope.chars().take(200).collect())
        .collect();
    let details = json!({"session_id":session.to_string(), "grant_type":"authorization_code", "scope":bounded});
    if details.to_string().len() > 2048 {
        json!({"truncated":true})
    } else {
        details
    }
}

impl GrantSessionIssuer {
    /// Issue a code grant and record its decision. Roll back the transaction on any error.
    pub async fn issue_code_response(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        claimed: &ClaimedGrant,
        settings: &GrantSettings<'_>,
        origin: SessionOrigin<'_>,
        request_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<TokenResponse, SessionError> {
        let response = self
            .issue_grant_response(tx, claimed, settings, origin, now)
            .await?;
        let user = claimed.grant.user_id;
        let (email, organization) = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
            "SELECT primary_email, organization_id FROM users WHERE id=$1",
        )
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
        write_event(
            &mut **tx,
            GrantEvent {
                user: Some(user),
                email,
                organization,
                client: &claimed.grant.client_id,
                reason: None,
                details: grant_details(claimed.session_id, &response.scope),
            },
            origin,
            request_id,
            now,
        )
        .await?;
        Ok(response)
    }
}

pub(crate) struct GrantEvent<'a> {
    pub user: Option<Uuid>,
    pub email: Option<String>,
    pub organization: Option<Uuid>,
    pub client: &'a str,
    pub reason: Option<&'static str>,
    pub details: Value,
}

pub(crate) async fn write_event<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    event: GrantEvent<'_>,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let GrantEvent {
        user,
        email,
        organization,
        client,
        reason,
        details,
    } = event;
    write_activity(
        executor,
        AuditActivity::Grant {
            client,
            reason,
            details,
        },
        AuditSubject {
            user,
            email,
            organization,
        },
        origin,
        request_id,
        now,
    )
    .await
}

pub(crate) struct AuditSubject {
    pub user: Option<Uuid>,
    pub email: Option<String>,
    pub organization: Option<Uuid>,
}

pub(crate) enum AuditActivity<'a> {
    Grant {
        client: &'a str,
        reason: Option<&'static str>,
        details: Value,
    },
    PasswordChanged(Result<u64, &'static str>),
    PasswordReset(Result<u64, &'static str>),
    ResetRequested(Option<&'static str>),
    EmailVerified(Option<&'static str>),
    Registration(Option<&'static str>),
    PhoneEdit,
    EmailDecision {
        reason: Option<&'static str>,
    },
    PasswordLogin(Uuid),
    PasskeyLogin(Uuid, Uuid),
    PasskeyRefused(bool),
    PasskeyChallenge,
    PasskeyRevoked(Uuid),
    PasskeyEnrolled(Uuid),
    LogoffAll(u64),
    Authenticator(&'static str, Option<&'static str>),
    Logoff {
        protocol: Option<&'static str>,
        reason: Option<&'static str>,
        details: Value,
    },
    Refresh {
        session: Option<Uuid>,
        reason: Option<&'static str>,
    },
    FactorLogin(Uuid, &'static str, &'static str),
    FactorRefused(&'static str, &'static str),
    EmailLogin(Uuid),
    EmailLoginRefused(&'static str),
    PasswordRefused(&'static str),
    MfaChallenge {
        method: &'static str,
        delivery_failed: bool,
    },
    LoginRateLimited,
}

fn outcome(failed: bool) -> &'static str {
    if failed { "failure" } else { "success" }
}

pub(crate) async fn write_activity<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    activity: AuditActivity<'_>,
    subject: AuditSubject,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let AuditSubject {
        user,
        email,
        organization,
    } = subject;
    let is_mfa = matches!(
        activity,
        AuditActivity::FactorLogin(_, _, _) | AuditActivity::PasskeyLogin(_, _)
    );
    let (class, activity, protocol, client, outcome, reason, details) = match activity {
        AuditActivity::Grant {
            client,
            reason,
            details,
        } => (
            "authorization",
            "token_grant",
            Some("oidc"),
            client,
            outcome(reason.is_some()),
            reason,
            details,
        ),
        AuditActivity::PasskeyLogin(session, key) => (
            "authentication",
            "logon",
            Some("passkey"),
            "",
            "success",
            None,
            json!({"session_id":session,"passkey_id":key}),
        ),
        AuditActivity::PasskeyRefused(counter) => (
            "authentication",
            "logon",
            Some("passkey"),
            "",
            "failure",
            Some("invalid_passkey"),
            json!({"counter_anomaly":counter}),
        ),
        AuditActivity::PasskeyChallenge => (
            "authentication",
            "mfa_challenge",
            Some("passkey"),
            "",
            "success",
            Some("mfa_required"),
            json!({"method":"totp"}),
        ),
        AuditActivity::EmailLogin(session) => (
            "authentication",
            "logon",
            Some("magic_link"),
            "",
            "success",
            None,
            json!({"session_id":session, "primary":"pwd"}),
        ),
        AuditActivity::EmailLoginRefused(reason) => (
            "authentication",
            "logon",
            Some("magic_link"),
            "",
            "failure",
            Some(reason),
            json!({}),
        ),
        AuditActivity::FactorLogin(session, method, primary) => (
            "authentication",
            "mfa_verify",
            Some(method),
            "",
            "success",
            None,
            json!({"session_id":session,"primary":primary}),
        ),
        AuditActivity::FactorRefused(reason, primary) => (
            "authentication",
            "mfa_verify",
            None,
            "",
            "failure",
            Some(reason),
            if reason == "mfa_failed" {
                json!({"primary":primary})
            } else {
                json!({})
            },
        ),
        AuditActivity::PasskeyRevoked(id) | AuditActivity::PasskeyEnrolled(id) => (
            "credential",
            if matches!(activity, AuditActivity::PasskeyEnrolled(_)) {
                "passkey_enroll"
            } else {
                "passkey_revoke"
            },
            Some("passkey"),
            "",
            "success",
            None,
            json!({"passkey_id":id}),
        ),
        AuditActivity::Authenticator(activity, reason) => (
            "credential",
            activity,
            Some("totp"),
            "",
            outcome(reason.is_some()),
            reason,
            json!({}),
        ),
        AuditActivity::Registration(reason) => (
            "account_lifecycle",
            "register",
            if reason == Some("rate_limited") {
                None
            } else {
                Some("password")
            },
            "",
            outcome(reason.is_some()),
            reason,
            json!({}),
        ),
        AuditActivity::EmailVerified(reason) => (
            "account_lifecycle",
            "email_verify",
            None,
            "",
            outcome(reason.is_some()),
            reason,
            json!({}),
        ),
        AuditActivity::ResetRequested(reason) => (
            "credential",
            "password_reset_request",
            None,
            "",
            outcome(reason.is_some()),
            reason,
            json!({}),
        ),
        AuditActivity::PasswordReset(result) => (
            "credential",
            "password_reset_confirm",
            None,
            "",
            outcome(result.is_err()),
            result.err(),
            result
                .map(|count| json!({"sessions_revoked":count}))
                .unwrap_or_else(|_| json!({})),
        ),
        AuditActivity::PasswordChanged(result) => (
            "credential",
            "password_change",
            Some("password"),
            "",
            outcome(result.is_err()),
            result.err(),
            result
                .map(|count| json!({"sessions_revoked":count}))
                .unwrap_or_else(|_| json!({})),
        ),
        AuditActivity::LogoffAll(count) => (
            "session",
            "logoff_all",
            None,
            "",
            "success",
            None,
            json!({"sessions_revoked":count}),
        ),
        AuditActivity::Logoff {
            protocol,
            reason,
            details,
        } => (
            "session",
            "logoff",
            protocol,
            "",
            outcome(reason.is_some()),
            reason,
            details,
        ),
        AuditActivity::Refresh { session, reason } => (
            "session",
            "token_refresh",
            Some("refresh_token"),
            "",
            outcome(reason.is_some()),
            reason,
            session.map_or_else(|| json!({}), |id| json!({"session_id":id})),
        ),
        AuditActivity::PasswordLogin(session) => (
            "authentication",
            "logon",
            Some("password"),
            "",
            "success",
            None,
            json!({"session_id":session}),
        ),
        AuditActivity::EmailDecision { reason } => (
            "authentication",
            "magic_link_decision",
            if reason == Some("invalid_token") {
                None
            } else {
                Some("magic_link")
            },
            "",
            outcome(reason.is_some()),
            reason,
            json!({}),
        ),
        AuditActivity::PhoneEdit => (
            "account_lifecycle",
            "subject_rectification",
            None,
            "",
            "success",
            None,
            json!({"fields":["phone"]}),
        ),
        AuditActivity::PasswordRefused(reason) => (
            "authentication",
            "logon",
            Some("password"),
            "",
            "failure",
            Some(reason),
            json!({}),
        ),
        AuditActivity::LoginRateLimited => (
            "authentication",
            "logon",
            None,
            "",
            "failure",
            Some("rate_limited"),
            json!({}),
        ),
        AuditActivity::MfaChallenge {
            method,
            delivery_failed,
        } => (
            "authentication",
            "mfa_challenge",
            Some("password"),
            "",
            outcome(delivery_failed),
            Some(if delivery_failed {
                "provider_error"
            } else {
                "mfa_required"
            }),
            json!({"method":method}),
        ),
    };
    let email = email.filter(|s| !s.is_empty()).map(|s| {
        s.trim()
            .to_lowercase()
            .chars()
            .take(320)
            .collect::<String>()
    });
    let subject = user.map(|id| id.to_string());
    let subject_format = if email.is_some() {
        Some("email")
    } else {
        user.map(|_| "opaque")
    };
    let timestamp = now.format("%Y-%m-%dT%H:%M:%S%.6f").to_string();
    let mut event = json!({
        "id": Uuid::new_v4().to_string(),
        "occurred_at": timestamp,
        "schema_version": 1,
        "event_class": class,
        "activity": activity,
        "outcome": outcome,
        "reason_code": reason,
        "auth_protocol": protocol,
        "is_mfa": is_mfa,
        "subject_format": subject_format,
        "subject_identifier": subject.as_ref().filter(|_| email.is_none()),
        "subject_user_id": subject,
        "subject_email": email,
        "subject_issuer": null,
        "actor_type": "user",
        "actor_user_id": subject,
        "actor_client_id": null,
        "client_id": (!client.is_empty()).then(||client.chars().take(128).collect::<String>()),
        "organization_id": organization.map(|id| id.to_string()),
        "ip_address": origin.ip.map(|ip| ip.to_string()),
        "request_id": request_id.filter(|id| valid_request_id(id)),
        "user_agent": origin.user_agent.filter(|s| !s.is_empty()).map(|s| s.chars().take(512).collect::<String>()),
        "details": details
    });
    event.sort_all_objects();
    let digest = Sha256::digest(event.to_string().as_bytes());
    event["content_hash"] = json!(format!("{digest:x}"));
    // The hash uses a UTC wall-clock value. Give PostgreSQL an explicit zone on input.
    event["occurred_at"] = json!(format!("{timestamp}Z"));
    sqlx::query(
        "INSERT INTO auth_events SELECT * FROM jsonb_populate_record(NULL::auth_events, $1)",
    )
    .bind(event)
    .execute(executor)
    .await?;
    Ok(())
}
