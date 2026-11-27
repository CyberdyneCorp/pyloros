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
    let operator = Operator {
        id: actor.0,
        origin,
        request,
    };
    let (id, wallet) =
        match create_verified(&mut tx, state, &email, password, &operator, None).await? {
            Creation::Created(id, wallet) => (id, wallet),
            Creation::Existing | Creation::ConcurrentDuplicate => {
                return Ok(problem(StatusCode::CONFLICT, "Email already registered"));
            }
            Creation::Unavailable(message) => {
                return Ok(problem(StatusCode::SERVICE_UNAVAILABLE, message));
            }
        };
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

pub(super) struct Operator<'a> {
    pub(super) id: Uuid,
    pub(super) origin: SessionOrigin<'a>,
    pub(super) request: Option<&'a str>,
}

pub(super) enum Creation {
    Created(Uuid, ManagedWallet),
    Existing,
    ConcurrentDuplicate,
    Unavailable(&'static str),
}

pub(super) async fn create_verified(
    tx: &mut Transaction<'_, Postgres>,
    state: &Profile,
    email: &str,
    password: String,
    operator: &Operator<'_>,
    row: Option<usize>,
) -> Result<Creation, Box<dyn Error + Send + Sync>> {
    if email_exists(&mut **tx, email).await? {
        return Ok(Creation::Existing);
    }
    let settings = &state.registration;
    let Some(key) = &settings.key else {
        return Ok(Creation::Unavailable("Wallet encryption key unavailable"));
    };
    let wallet = ManagedWallet::generate(key)?;
    let hash = state.scheme.hash(password).await?;
    if settings.hooks && needs_dispatcher(tx).await? {
        return Ok(Creation::Unavailable(
            "Registration hook dispatcher unavailable",
        ));
    }
    let id = Uuid::new_v4();
    if !insert_user(tx, id, email, &hash, &wallet, true).await? {
        return Ok(Creation::ConcurrentDuplicate);
    }
    let now = Utc::now();
    if settings.webhooks {
        enqueue_webhooks(tx, id, now).await?;
    }
    write_activity(
        &mut **tx,
        AuditActivity::UserCreated {
            operator: operator.id,
            row,
        },
        AuditSubject {
            user: Some(id),
            email: Some(email.to_owned()),
            organization: None,
        },
        operator.origin,
        operator.request,
        now,
    )
    .await?;
    Ok(Creation::Created(id, wallet))
}
