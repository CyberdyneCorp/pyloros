//! Apply a signed device verification form to one pending request.
use super::{Browser, PageResult, unavailable};
use crate::grant_audit::{AuditActivity, AuditSubject, write_activity};
use crate::grant_response::SessionOrigin;
use crate::token_http::{client_ip, header};
use crate::token_runtime::Runtime;
use crate::{
    browser_client::grant::BrowserSession,
    consent_http::{Ticket, grant},
};
use axum::extract::Request;
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use chrono::Utc;
use minijinja::context;
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeSet;
use std::{net::SocketAddr, sync::Arc};
use uuid::Uuid;

pub(super) async fn submit(
    State(browser): State<Arc<Browser>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let Some(rt) = &browser.runtime else {
        return unavailable();
    };
    if browser.templates.is_none() {
        return unavailable();
    }
    let headers = req.headers().clone();
    let form = match crate::token_http::fields(req).await {
        Ok(fields) => fields,
        Err(response) => return *response,
    };
    let field = |name: &str| {
        form.iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_default()
    };
    browser
        .decide(rt, &headers, peer, field("ticket"), field("decision"))
        .await
        .unwrap_or_else(|_| crate::token_http::internal())
}

impl Browser {
    fn form_error(&self, message: &str) -> PageResult {
        self.render(
            "error",
            StatusCode::BAD_REQUEST,
            context! {error=>format!("{message}. Start again from your device.")},
        )
    }
    async fn decide(
        &self,
        rt: &Runtime,
        headers: &HeaderMap,
        peer: SocketAddr,
        raw: &str,
        decision: &str,
    ) -> PageResult {
        let mut tx = rt.pool.begin().await?;
        let Some(session) = rt
            .verifier
            .browser_session(headers, &mut tx, rt.enforce_revocation)
            .await?
        else {
            return self.render(
                "error",
                StatusCode::UNAUTHORIZED,
                context! {error=>"You are not signed in. Start again from your device."},
            );
        };
        let approved = match decision {
            "approve" => true,
            "deny" => false,
            _ => return self.form_error("decision must be approve or deny"),
        };
        let target = rt
            .verifier
            .consent_ticket(raw)
            .and_then(|ticket| device_target(ticket, session.user));
        let origin = SessionOrigin {
            ip: client_ip(headers, peer.ip(), self.proxies),
            user_agent: header(headers, "user-agent"),
        };
        let subject = AuditSubject {
            user: Some(session.user),
            email: None,
            organization: None,
        };
        let request_id = header(headers, "x-request-id");
        let Some((id, ticket)) = target else {
            tx.rollback().await?;
            if write_activity(
                &rt.pool,
                AuditActivity::DeviceLookup("", "invalid_state"),
                subject,
                origin,
                request_id,
                Utc::now(),
            )
            .await
            .is_err()
            {
                eprintln!("could not record device decision refusal");
            }
            return self.form_error("invalid or expired form");
        };
        let (name, trusted) = match update(&mut tx, id, &ticket, &session, approved).await? {
            Ok(client) => client,
            Err(message) => return self.form_error(message),
        };
        if approved && !trusted {
            grant(&mut tx, &ticket).await?;
        }
        let scopes: Vec<String> = ticket
            .scope
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|s| s.chars().take(200).collect())
            .collect();
        let mut details = json!({"scope":scopes,"device_authorization_id":id});
        if details.to_string().len() > 2048 {
            details = json!({"truncated":true});
        }
        write_activity(
            &mut *tx,
            AuditActivity::DeviceDecision {
                client: &ticket.client_id,
                approved,
                details,
            },
            subject,
            origin,
            request_id,
            Utc::now(),
        )
        .await?;
        let response = self.render(
            if approved { "approved" } else { "denied" },
            StatusCode::OK,
            context! {client_name=>name},
        )?;
        tx.commit().await?;
        Ok(response)
    }
}

fn device_target(ticket: Ticket, user: Uuid) -> Option<(Uuid, Ticket)> {
    if ticket.sub != user || !ticket.resource.is_empty() {
        return None;
    }
    let id = ticket
        .authz
        .strip_prefix("device_authorization=")?
        .parse()
        .ok()?;
    Some((id, ticket))
}

async fn update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    ticket: &Ticket,
    session: &BrowserSession,
    approved: bool,
) -> Result<Result<(String, bool), &'static str>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT client_id, scopes FROM device_authorizations
         WHERE id=$1 AND status='pending' AND expires_at>now()",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(Err("this request is no longer pending"));
    };
    if row.try_get::<&str, _>("client_id")? != ticket.client_id
        || row
            .try_get::<&str, _>("scopes")?
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            != ticket.scope.split_whitespace().collect()
    {
        return Ok(Err("this request is no longer pending"));
    }
    let client = sqlx::query_as::<_, (String, bool)>(
        "SELECT name, trusted FROM oauth_clients
         WHERE client_id=$1 AND active AND registration_source<>'dynamic'
           AND $2=ANY(regexp_split_to_array(grant_types,'[[:space:]]+')) FOR SHARE",
    )
    .bind(&ticket.client_id)
    .bind(super::super::device::GRANT)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(client) = client else {
        return Ok(Err("client unavailable"));
    };
    let amr = session
        .authenticated_at
        .map(|_| session.amr.as_deref().unwrap_or_default());
    let changed = sqlx::query(
        "UPDATE device_authorizations SET status=$2, user_id=$3, auth_time=$4, amr=$5, decided_at=clock_timestamp()
         WHERE id=$1 AND status='pending' AND expires_at>clock_timestamp()",
    )
    .bind(id)
    .bind(if approved {"approved"} else {"denied"})
    .bind(session.user)
    .bind(session.authenticated_at)
    .bind(amr)
    .execute(&mut **tx)
    .await?;
    if changed.rows_affected() == 0 {
        return Ok(Err("this request was already decided"));
    }
    Ok(Ok(client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_signed_in_users_device_form_can_decide_a_request() {
        let user = Uuid::new_v4();
        let target = Uuid::new_v4();
        let ticket = || Ticket {
            kind: "consent".into(),
            sub: user,
            client_id: "device".into(),
            resource: String::new(),
            scope: "openid".into(),
            authz: format!("device_authorization={target}"),
        };
        assert_eq!(device_target(ticket(), user).unwrap().0, target);
        assert!(device_target(ticket(), Uuid::new_v4()).is_none());
        let mut browser_form = ticket();
        browser_form.authz =
            format!("redirect_uri=https%3A%2F%2Fclient.example&device_authorization={target}");
        assert!(device_target(browser_form, user).is_none());
        let mut resource_form = ticket();
        resource_form.resource = "https://resource.example".into();
        assert!(device_target(resource_form, user).is_none());
    }
}
