//! Erase an account and its linked personal data in a single transaction.
mod activity;
mod records;
mod report;
use super::subject_identifiers::Identifiers;
use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    token_http::{client_ip, header as value},
};
use axum::extract::Path;
use report::Counts;
pub(super) use report::Settings;

pub(super) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (tx, actor, _) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let user = match crate::query::path_uuid(&raw, "user_id") {
        Ok(v) => v,
        Err(e) => return passkeys::validation(vec![e]),
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    erase(
        tx,
        &state,
        user,
        actor,
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn erase(
    mut tx: Transaction<'_, Postgres>,
    state: &Profile,
    user: Uuid,
    operator: Uuid,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, sqlx::Error> {
    type Account = (Option<String>, Option<String>, Option<String>, Option<Uuid>);
    let row = sqlx::query_as::<_, Account>(
        "SELECT primary_email, primary_phone, default_wallet_address, organization_id
         FROM users WHERE id=$1",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, phone, wallet, org)) = row else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    if state.registration.hooks
        && !wasm_hooks::delivery::enqueue(
            &mut tx,
            wasm_hooks::delivery::Producer::Erasure,
            "user_deleted",
            Some(user),
            json!({}),
        )
        .await?
    {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Deletion hook dispatcher unavailable",
        ));
    }
    let ids = Identifiers::collect(
        &mut tx,
        user,
        email.as_deref(),
        phone.as_deref(),
        wallet.as_deref(),
    )
    .await?;
    let sessions = logout_all::revoke_sessions(&mut tx, user, Utc::now()).await?;
    let counts = records::erase(&mut tx, user, &ids).await?;
    let totals = state.erasure.totals(&counts, sessions);
    let subject = || AuditSubject {
        user: Some(user),
        email: None,
        organization: org,
    };
    if let Some(&count) = counts.rewritten.get("auth_events") {
        write_activity(
            &mut *tx,
            AuditActivity::EventsPseudonymised { operator, count },
            subject(),
            origin,
            request,
            Utc::now(),
        )
        .await?;
    }
    write_activity(
        &mut *tx,
        AuditActivity::AccountErased {
            operator,
            totals: totals.clone(),
        },
        subject(),
        origin,
        request,
        Utc::now(),
    )
    .await?;
    if state.registration.webhooks {
        registration::enqueue_account_event(&mut tx, user, Utc::now(), "user.deleted").await?;
    }
    audit_erasure(&mut tx, operator, user, totals, origin).await?;
    tx.commit().await?;
    Ok(Json(json!({
        "user_id": user, "email": email, "wallet_address": wallet,
        "sessions_revoked": sessions, "message": "User deleted successfully",
        "erasure": state.erasure.render(&counts)
    }))
    .into_response())
}

async fn audit_erasure(
    tx: &mut Transaction<'_, Postgres>,
    operator: Uuid,
    user: Uuid,
    totals: Value,
    origin: SessionOrigin<'_>,
) -> Result<(), sqlx::Error> {
    let actor_email =
        sqlx::query_scalar::<_, Option<String>>("SELECT primary_email FROM users WHERE id=$1")
            .bind(operator)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    crate::admin_audit::append(
        tx,
        "user.delete",
        Some((operator, actor_email.as_deref())),
        ("user", &user.to_string()),
        totals,
        origin,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn deletion_audit_resolves_the_operator_after_erasure() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE users(id uuid PRIMARY KEY, primary_email text);
            CREATE TEMP TABLE audit_chain_head(id int PRIMARY KEY, head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid, action text, target_type text,
                target_id text, extra_metadata jsonb, ip_address inet, user_agent text,
                created_at timestamptz, prev_hash text, row_hash text, actor_user_id uuid,
                actor_type text,actor_client_id text,actor_email text);",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let operator = Uuid::new_v4();
        let managed = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES ($1,'operator@example.test')")
            .bind(operator)
            .execute(&mut *tx)
            .await
            .unwrap();
        let origin = SessionOrigin {
            ip: None,
            user_agent: None,
        };
        audit_erasure(&mut tx, operator, managed, json!({}), origin)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(operator)
            .execute(&mut *tx)
            .await
            .unwrap();
        audit_erasure(&mut tx, operator, operator, json!({}), origin)
            .await
            .unwrap();
        for (target, email) in [(managed, Some("operator@example.test")), (operator, None)] {
            let recorded = sqlx::query_as::<_, (Uuid, Option<String>)>(
                "SELECT actor_user_id,actor_email FROM admin_action_logs WHERE target_id=$1",
            )
            .bind(target.to_string())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(recorded.0, operator);
            assert_eq!(recorded.1.as_deref(), email);
        }
    }
}
