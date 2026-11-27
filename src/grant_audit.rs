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

fn grant_details(kind: &str, session: Uuid, scopes: &str) -> Value {
    let bounded: Vec<String> = scopes
        .split_ascii_whitespace()
        .map(|scope| scope.chars().take(200).collect())
        .collect();
    let details = json!({"session_id":session.to_string(), "grant_type":kind, "scope":bounded});
    if details.to_string().len() > 2048 {
        json!({"truncated":true})
    } else {
        details
    }
}

impl GrantSessionIssuer {
    /// Issue a code grant and record its decision. ID-token refusal retains the issued session and grant event.
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
            .await;
        let scope = match &response {
            Ok(tokens) => &tokens.scope,
            Err(SessionError::UnsupportedIdToken) => &claimed.grant.sorted_scopes(),
            Err(_) => return response,
        };
        let event = GrantEvent::issued(
            tx,
            claimed.grant.user_id,
            &claimed.grant.client_id,
            "authorization_code",
            claimed.session_id,
            scope,
        )
        .await?;
        self.record_user_grant(tx, event, origin, request_id, now)
            .await?;
        response
    }

    pub(crate) async fn record_user_grant(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event: GrantEvent<'_>,
        origin: SessionOrigin<'_>,
        request_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), SessionError> {
        if self.login_hooks
            && let Some(user) = event.user
            && !crate::profile::logged_in(tx, user, event.email.as_deref(), origin).await?
        {
            return Err(SessionError::HookUnavailable);
        }
        write_event(&mut **tx, event, origin, request_id, now).await?;
        Ok(())
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

impl<'a> GrantEvent<'a> {
    pub(crate) async fn issued(
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
        client: &'a str,
        kind: &str,
        session: Uuid,
        scope: &str,
    ) -> Result<Self, sqlx::Error> {
        let (email, organization) = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
            "SELECT primary_email, organization_id FROM users WHERE id=$1",
        )
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
        Ok(Self {
            user: Some(user),
            email,
            organization,
            client,
            reason: None,
            details: grant_details(kind, session, scope),
        })
    }
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
    DeviceDecision {
        client: &'a str,
        approved: bool,
        details: Value,
    },
    DeviceLookup(&'a str, &'static str),
    DeviceStart(&'a str, Option<&'static str>, Value),
    Revoke {
        client: &'a str,
        reason: Option<&'static str>,
        details: Value,
    },
    CliExchange {
        provider: Option<String>,
        reason: Option<&'static str>,
    },
    Federated {
        identity: Option<(&'a str, &'a str)>,
        reason: Option<&'a str>,
        details: serde_json::Value,
    },
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
    Wallet {
        did: Option<&'a str>,
        reason: Option<&'static str>,
        details: Value,
    },
    PasswordLogin(Uuid),
    PasskeyLogin(Uuid, Uuid),
    PasskeyRefused(bool),
    PasskeyChallenge,
    AdminPasswordReset {
        operator: Uuid,
        sessions: u64,
    },
    SubjectExport {
        operator: Option<Uuid>,
        counts: Value,
    },
    AccountErased {
        operator: Uuid,
        totals: Value,
    },
    EventsPseudonymised {
        operator: Uuid,
        count: i64,
    },
    AdminRole {
        operator: Uuid,
        grant: bool,
        previous: Result<bool, &'static str>,
    },
    AdminMfaReset {
        operator: Uuid,
        was_enabled: bool,
    },
    AdminPasskeyRevoked {
        operator: Uuid,
        key: Uuid,
    },
    PasskeyRevoked(Uuid),
    PasskeyEnrolled(Uuid),
    LogoffAll(u64),
    ServiceUserCreated(&'a str),
    UserCreated {
        operator: Uuid,
        row: Option<usize>,
    },
    SessionRevoked {
        operator: Uuid,
        session: Uuid,
    },
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

// Class, activity, protocol, client, outcome, reason and activity-specific details.
type Classification<'a> = (
    &'static str,
    &'static str,
    Option<&'a str>,
    &'a str,
    &'static str,
    Option<&'a str>,
    Value,
);

fn classify(activity: AuditActivity<'_>) -> Classification<'_> {
    match activity {
        AuditActivity::ServiceUserCreated(client) => (
            "account_lifecycle",
            "user_create",
            None,
            client,
            "success",
            None,
            json!({}),
        ),
        AuditActivity::UserCreated { row, .. } => (
            "account_lifecycle",
            "user_create",
            None,
            "",
            "success",
            None,
            row.map_or_else(|| json!({}), |row| json!({"bulk_row":row})),
        ),
        AuditActivity::SessionRevoked { session, .. } => (
            "session",
            "session_revoke",
            None,
            "",
            "success",
            None,
            json!({"session_id":session}),
        ),
        AuditActivity::DeviceDecision {
            client,
            approved,
            details,
        } => (
            "authorization",
            if approved {
                "device_approve"
            } else {
                "device_deny"
            },
            None,
            client,
            "success",
            None,
            details,
        ),
        AuditActivity::DeviceLookup(client, reason) => (
            "authorization",
            "device_approve",
            None,
            client,
            "failure",
            Some(reason),
            json!({}),
        ),
        AuditActivity::DeviceStart(client, reason, details) => (
            "authorization",
            "device_authorize",
            None,
            client,
            outcome(reason.is_some()),
            reason,
            details,
        ),
        AuditActivity::Revoke {
            client,
            reason,
            details,
        } => (
            "session",
            "token_revoke",
            Some("oidc"),
            client,
            outcome(reason.is_some()),
            reason,
            details,
        ),
        AuditActivity::CliExchange { provider, reason } => {
            let mut details = json!({"grant_type":"cli_login_code"});
            if let Some(provider) = provider {
                details["provider"] = json!(provider);
            }
            (
                "authorization",
                "token_grant",
                reason.is_none().then_some("oauth2"),
                "",
                outcome(reason.is_some()),
                reason,
                details,
            )
        }
        AuditActivity::Wallet {
            reason, details, ..
        } => (
            "authentication",
            "logon",
            Some("siwe"),
            "",
            outcome(reason.is_some()),
            reason,
            details,
        ),
        AuditActivity::Federated {
            reason, details, ..
        } => (
            "authentication",
            "logon",
            Some("oauth2"),
            "",
            outcome(reason.is_some()),
            reason,
            details,
        ),
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
        AuditActivity::AdminPasswordReset { sessions, .. } => (
            "credential",
            "admin_password_reset",
            None,
            "",
            "success",
            None,
            json!({"sessions_revoked":sessions}),
        ),
        AuditActivity::SubjectExport { counts, .. } => (
            "account_lifecycle",
            "subject_export",
            None,
            "",
            "success",
            None,
            counts,
        ),
        AuditActivity::AccountErased { totals, .. } => (
            "account_lifecycle",
            "user_delete",
            None,
            "",
            "success",
            None,
            totals,
        ),
        AuditActivity::EventsPseudonymised { count, .. } => (
            "account_lifecycle",
            "auth_events_pseudonymised",
            None,
            "",
            "success",
            None,
            json!({"rows":count}),
        ),
        AuditActivity::AdminRole {
            grant, previous, ..
        } => (
            "authorization",
            if grant { "admin_grant" } else { "admin_revoke" },
            None,
            "",
            outcome(previous.is_err()),
            previous.err(),
            previous.map_or_else(|_| json!({}), |old| json!({"was_admin":old})),
        ),
        AuditActivity::AdminMfaReset { was_enabled, .. } => (
            "credential",
            "admin_mfa_reset",
            None,
            "",
            "success",
            None,
            json!({"was_enabled":was_enabled}),
        ),
        AuditActivity::AdminPasskeyRevoked { key, .. } => (
            "credential",
            "passkey_revoke",
            None,
            "",
            "success",
            None,
            json!({"passkey_id":key}),
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
            (reason != Some("rate_limited")).then_some("password"),
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
            (reason != Some("invalid_token")).then_some("magic_link"),
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
    }
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
    let operator = match &activity {
        AuditActivity::SubjectExport { operator, .. } => *operator,
        AuditActivity::SessionRevoked { operator, .. }
        | AuditActivity::AdminPasswordReset { operator, .. }
        | AuditActivity::AccountErased { operator, .. }
        | AuditActivity::EventsPseudonymised { operator, .. }
        | AuditActivity::AdminRole { operator, .. }
        | AuditActivity::AdminMfaReset { operator, .. }
        | AuditActivity::AdminPasskeyRevoked { operator, .. }
        | AuditActivity::UserCreated { operator, .. } => Some(*operator),
        _ => None,
    };
    let is_mfa = matches!(
        activity,
        AuditActivity::FactorLogin(_, _, _) | AuditActivity::PasskeyLogin(_, _)
    );
    let wallet_identifier = match &activity {
        AuditActivity::Wallet { did, .. } => *did,
        _ => None,
    };
    let federated_identity = match &activity {
        AuditActivity::Federated { identity, .. } => *identity,
        _ => None,
    };
    let (class, activity, protocol, client, outcome, reason, details) = classify(activity);
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
    if let Some(did) = wallet_identifier {
        event["subject_format"] = json!("did");
        event["subject_identifier"] = json!(did);
    }
    if let Some(operator) = operator {
        event["actor_type"] = json!("admin");
        event["actor_user_id"] = json!(operator);
    }
    if let Some((provider, identifier)) = federated_identity {
        event["subject_format"] = json!("iss_sub");
        event["subject_issuer"] = json!(provider.chars().take(255).collect::<String>());
        event["subject_identifier"] = json!(identifier.chars().take(255).collect::<String>());
    }
    if matches!(activity, "token_revoke" | "user_create") && !client.is_empty() {
        event["actor_type"] = json!("client");
        event["actor_user_id"] = Value::Null;
        event["actor_client_id"] = event["client_id"].clone();
    }
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
