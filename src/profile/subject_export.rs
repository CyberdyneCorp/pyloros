//! Download the personal data held about an account.
use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    login_throttle::RateLimited,
};
use axum::extract::Path;
use std::collections::HashMap;
mod sections;

pub(super) fn quota() -> crate::login_throttle::LoginThrottle {
    crate::login_throttle::LoginThrottle::with_window(3, std::time::Duration::from_secs(3600))
}

pub(super) fn routes() -> Router<Arc<Profile>> {
    Router::new()
        .route("/api/v1/users/me/export", any(read))
        .route("/api/v1/admin/users/{user_id}/export", any(read))
}

type Operator = (Uuid, Option<String>);

async fn read(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (tx, user, operator) = if let Some(raw) = path.get("user_id") {
        let (tx, operator, email) = match administrator::operator(&state, &headers).await {
            Ok(v) => v,
            Err(e) => return *e,
        };
        let user = match crate::query::path_uuid(raw, "user_id") {
            Ok(u) => u,
            Err(e) => return passkeys::validation(vec![e]),
        };
        (tx, user, Some((operator, email)))
    } else {
        match owner(&state, &headers).await {
            Ok((tx, user)) => (tx, user, None),
            Err(error) => return *error,
        }
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    export(
        tx,
        &state,
        user,
        operator,
        origin,
        crate::token_http::header(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn owner(
    state: &Profile,
    headers: &HeaderMap,
) -> Result<(Transaction<'static, Postgres>, Uuid), Box<Response>> {
    let identity =
        administrator::identity(state, headers).ok_or_else(|| Box::new(unauthorized()))?;
    let mut tx = state.pool.begin().await.map_err(|_| Box::new(internal()))?;
    if state.enforce
        && account_revoked(&mut tx, &identity)
            .await
            .map_err(|_| Box::new(internal()))?
    {
        return Err(Box::new(unauthorized()));
    }
    if !state
        .export_quota
        .allow_client(Some(&identity.user.to_string()), None)
    {
        let mut error = RateLimited.into_response();
        error.headers_mut().insert(
            header::RETRY_AFTER,
            header::HeaderValue::from_static("3600"),
        );
        return Err(Box::new(error));
    }
    Ok((tx, identity.user))
}

#[derive(serde::Serialize)]
struct Download {
    format_version: u8,
    user_id: Uuid,
    generated_at: String,
    sections: Vec<sections::Section>,
    processors: Value,
}

async fn export(
    mut tx: Transaction<'_, Postgres>,
    state: &Profile,
    user: Uuid,
    operator: Option<Operator>,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> sqlx::Result<Response> {
    type Account = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<Uuid>,
        String,
    );
    let account:Option<Account>=sqlx::query_as("SELECT primary_email,primary_phone,default_wallet_address,organization_id,extra_metadata::text FROM users WHERE id=$1")
        .bind(user).fetch_optional(&mut *tx).await?;
    let Some((email, phone, wallet, organization, metadata)) = account else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    administrator::validate_metadata(&metadata)?;
    let ids = subject_identifiers::Identifiers::collect(
        &mut tx,
        user,
        email.as_deref(),
        phone.as_deref(),
        wallet.as_deref(),
    )
    .await?;
    let now = Utc::now();
    let sections = sections::collect(
        &mut tx,
        &state.erasure,
        user,
        &ids,
        now - chrono::Duration::days(90),
    )
    .await?;
    let processors = state
        .erasure
        .processors(|t| sections.iter().any(|s| s.table == t && !s.rows.is_empty()));
    let counts = json!({"sections":sections.len(),"rows":sections.iter().map(|s|s.rows.len()).sum::<usize>()});
    write_activity(
        &mut *tx,
        AuditActivity::SubjectExport {
            operator: operator.as_ref().map(|o| o.0),
            counts: counts.clone(),
        },
        AuditSubject {
            user: Some(user),
            email,
            organization,
        },
        origin,
        request,
        Utc::now(),
    )
    .await?;
    if let Some((actor, email)) = operator {
        crate::admin_audit::append(
            &mut tx,
            "user.export",
            Some((actor, email.as_deref())),
            ("user", &user.to_string()),
            counts,
            origin,
        )
        .await?;
    }
    tx.commit().await?;
    let mut response = Json(Download {
        format_version: 1,
        user_id: user,
        generated_at: timestamp(now),
        sections,
        processors,
    })
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"cyberdyne-export-{user}.json\"")
            .parse()
            .expect("UUID attachment name"),
    );
    Ok(response)
}
