//! Operator-provisioned password accounts.
use super::*;

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match admin_fields::body(&headers, &bytes) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(body) = body else { return internal() };
    let credentials = match fields(body) {
        Ok(v) => v,
        Err(issues) => return password_change::invalid(issues),
    };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    provision(
        tx,
        &state,
        credentials,
        (actor, email.as_deref()),
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn provision(
    mut tx: Transaction<'_, Postgres>,
    state: &Profile,
    (email, password): (String, String),
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, Box<dyn Error + Send + Sync>> {
    let duplicate = || problem(StatusCode::CONFLICT, "Email already registered");
    if email_exists(&mut *tx, &email).await? {
        return Ok(duplicate());
    }
    let settings = &state.registration;
    let Some(key) = &settings.key else {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Wallet encryption key unavailable",
        ));
    };
    let wallet = ManagedWallet::generate(key)?;
    let hash = state.scheme.hash(password).await?;
    if settings.hooks && needs_dispatcher(&mut tx).await? {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Registration hook dispatcher unavailable",
        ));
    }
    let id = Uuid::new_v4();
    if !insert_user(&mut tx, id, &email, &hash, &wallet, true).await? {
        return Ok(duplicate());
    }
    let now = Utc::now();
    if settings.webhooks {
        enqueue_webhooks(&mut tx, id, now).await?;
    }
    write_activity(
        &mut *tx,
        AuditActivity::UserCreated(actor.0),
        AuditSubject {
            user: Some(id),
            email: Some(email.clone()),
            organization: None,
        },
        origin,
        request,
        now,
    )
    .await?;
    crate::admin_audit::append(
        &mut tx,
        "user.create",
        Some(actor),
        ("user", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(created_response(id, &email, &wallet))
}
