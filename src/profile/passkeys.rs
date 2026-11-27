mod binding_cookie;
mod creation;
mod rename;
mod revoke;
use super::*;
use crate::grant_response::SessionOrigin;
use crate::token_http::header as header_value;
use crate::{
    login_http::problem,
    login_throttle::{LoginThrottle, RateLimited},
    token_http::client_ip,
};
use serde::Serialize;

pub async fn limit_passkey_body(req: Request, next: axum::middleware::Next) -> Response {
    if !req.uri().path().starts_with("/api/v1/auth/passkeys") {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    match axum::body::to_bytes(body, 65536).await {
        Ok(bytes) => next.run(Request::from_parts(parts, bytes.into())).await,
        Err(_) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"detail":"Passkey request too large"})),
        )
            .into_response(),
    }
}

pub(super) struct Inventory {
    rp: Option<String>,
    creation: Option<creation::Settings>,
    start_quota: LoginThrottle,
    quota: LoginThrottle,
    rename_quota: LoginThrottle,
    revoke_quota: LoginThrottle,
}

impl Inventory {
    pub(super) fn configured() -> Result<Self, Box<dyn Error>> {
        let rp = crate::login_methods::passkey_rp(
            env::var("APP_ENV").unwrap_or_else(|_| "dev".into()) == "dev",
        )?;
        let limit = crate::token_runtime::number("PASSKEYS_RATE_LIMIT_PER_MIN", 10)?;
        if !(1..=100).contains(&limit) {
            return Err("invalid PASSKEYS_RATE_LIMIT_PER_MIN".into());
        }
        let mut inventory = Self::new(rp, limit);
        inventory.creation = inventory
            .rp
            .as_deref()
            .map(creation::Settings::configured)
            .transpose()?;
        Ok(inventory)
    }
    pub(super) fn new(rp: Option<String>, limit: i64) -> Self {
        Self {
            rp,
            creation: None,
            start_quota: LoginThrottle::new(limit),
            quota: LoginThrottle::new(limit),
            rename_quota: LoginThrottle::new(limit),
            revoke_quota: LoginThrottle::new(limit),
        }
    }
}

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    run(&state, &headers, peer.ip(), Operation::List).await
}

pub(super) async fn modify(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    axum::extract::Path(path): axum::extract::Path<String>,
    req: Request,
) -> Response {
    match *req.method() {
        Method::DELETE => {
            run(
                &state,
                req.headers(),
                peer.ip(),
                Operation::Revoke(rename::key_id(&path)),
            )
            .await
        }
        Method::PATCH => rename::handle(&state, peer, path, req).await,
        _ => {
            let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
            response
                .headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static("PATCH"));
            response
        }
    }
}

pub(super) async fn start_enrollment(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::POST {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
        return response;
    }
    let binding = state
        .passkeys
        .creation
        .as_ref()
        .and_then(|settings| settings.transport(&headers, peer.ip()));
    run(&state, &headers, peer.ip(), Operation::Enroll(binding)).await
}

enum Operation {
    Enroll(Option<creation::Transport>),
    List,
    Revoke(Result<Uuid, Value>),
    Rename(Result<(Uuid, String), Vec<Value>>),
}

fn validation(issues: Vec<Value>) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail":issues})),
    )
        .into_response()
}

async fn run(
    state: &Profile,
    headers: &HeaderMap,
    peer: std::net::IpAddr,
    operation: Operation,
) -> Response {
    let Some(id) = credential(headers)
        .and_then(|t| state.verify.as_ref()?.read(t))
        .filter(|id| !id.client_bound)
    else {
        return unauthorized();
    };
    let result = inventory(
        state,
        &id,
        SessionOrigin {
            ip: client_ip(headers, peer, state.proxies),
            user_agent: header_value(headers, "user-agent"),
        },
        header_value(headers, "x-request-id"),
        operation,
    )
    .await;
    result.unwrap_or_else(|_| {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Passkey inventory unavailable",
        )
    })
}

async fn inventory(
    state: &Profile,
    id: &Identity,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
    operation: Operation,
) -> Result<Response, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, id).await? {
        return Ok(unauthorized());
    }
    let Some(session) = id.sid else {
        return Ok(problem(
            StatusCode::UNAUTHORIZED,
            "First-party session required; sign in again",
        ));
    };
    let Some(rp) = &state.passkeys.rp else {
        return Ok(problem(StatusCode::NOT_FOUND, "Passkeys disabled"));
    };
    let quota = match &operation {
        Operation::Enroll(_) => &state.passkeys.start_quota,
        Operation::List => &state.passkeys.quota,
        Operation::Revoke(_) => &state.passkeys.revoke_quota,
        Operation::Rename(_) => &state.passkeys.rename_quota,
    };
    if !quota.allow(origin.ip) {
        return Ok(RateLimited.into_response());
    }
    if matches!(operation, Operation::Enroll(None)) {
        return Ok(problem(
            StatusCode::UNAUTHORIZED,
            "Invalid passkey ceremony or authentication proof",
        ));
    }
    if let Operation::Rename(Err(issues)) = operation {
        return Ok(validation(issues));
    }
    if let Operation::Revoke(Err(issue)) = operation {
        return Ok(validation(vec![issue]));
    }
    if matches!(operation, Operation::Revoke(_)) {
        // Acquire the account lock before inspecting sessions or alternative credentials.
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(id.user)
            .execute(&mut *tx)
            .await?;
    }
    let live=sqlx::query_scalar::<_,bool>(
        "SELECT u.totp_enabled FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2
        AND u.is_active AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND (u.tokens_valid_after IS NULL OR $3>floor(extract(epoch FROM u.tokens_valid_after))::bigint) FOR SHARE OF u,s"
    ).bind(id.user).bind(session).bind(id.iat).fetch_optional(&mut *tx).await?;
    let Some(mfa) = live else {
        return Ok(problem(
            StatusCode::UNAUTHORIZED,
            "Invalid passkey ceremony or authentication proof",
        ));
    };
    if let Operation::Enroll(Some(binding)) = operation {
        let settings = state
            .passkeys
            .creation
            .as_ref()
            .expect("validated enrollment settings");
        return creation::issue(tx, settings, id, rp, binding, mfa).await;
    }
    if let Operation::Revoke(Ok(key)) = operation {
        return revoke::apply(tx, id, rp, key, origin, request_id).await;
    }
    if let Operation::Rename(Ok((key, name))) = operation {
        let record = match rename::save(&mut tx, id.user, rp, key, name).await {
            Ok(Some(record)) => record,
            Ok(None) => return Ok(problem(StatusCode::NOT_FOUND, "Passkey not found")),
            Err(sqlx::Error::Database(error))
                if error.code().is_some_and(|code| code.starts_with("22")) =>
            {
                return Ok(internal());
            }
            Err(error) => return Err(error),
        };
        tx.commit().await?;
        return Ok(Json(record).into_response());
    }
    let rows = metadata(&mut tx, id.user, rp).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(rows)).into_response())
}

#[derive(Serialize)]
struct Record {
    id: Uuid,
    name: String,
    created_at: String,
    last_used_at: Option<String>,
    backup_eligible: bool,
    backed_up: bool,
}

async fn metadata(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    rp: &str,
) -> Result<Vec<Record>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id,name,created_at,last_used_at,backup_eligible,backed_up FROM passkeys
        WHERE user_id=$1 AND rp_id=$2 AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(user)
    .bind(rp)
    .fetch_all(&mut **tx)
    .await?;
    rows.into_iter().map(record).collect()
}

fn record(row: sqlx::postgres::PgRow) -> Result<Record, sqlx::Error> {
    use sqlx::Row;
    Ok(Record {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        created_at: timestamp(row.try_get("created_at")?),
        last_used_at: row
            .try_get::<Option<DateTime<Utc>>, _>("last_used_at")?
            .map(timestamp),
        backup_eligible: row.try_get("backup_eligible")?,
        backed_up: row.try_get("backed_up")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_passkey_requests_stop_before_dispatch() {
        use tower::ServiceExt;
        let route = "/api/v1/auth/passkeys/register/options";
        let app = Router::new()
            .route(route, any(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(limit_passkey_body));
        for (size, expected) in [
            (65536, StatusCode::NO_CONTENT),
            (65537, StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let req = Request::builder()
                .method("POST")
                .uri(route)
                .body(axum::body::Body::from(vec![0; size]))
                .unwrap();
            assert_eq!(app.clone().oneshot(req).await.unwrap().status(), expected);
        }
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn inventory_is_scoped_to_owner_relying_party_and_active_records() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE passkeys(id uuid,user_id uuid,rp_id text,name text,created_at timestamptz,last_used_at timestamptz,backup_eligible bool,backed_up bool,revoked_at timestamptz)").execute(&mut *tx).await.unwrap();
        let owner = Uuid::new_v4();
        let foreign = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO passkeys VALUES
            ($1,$1,'rp','current',now(),NULL,true,false,NULL),
            ($2,$2,'rp','foreign',now(),NULL,true,false,NULL),
            ($2,$1,'other','other RP',now(),NULL,true,false,NULL),
            ($2,$1,'rp','revoked',now(),NULL,true,false,now())",
        )
        .bind(owner)
        .bind(foreign)
        .execute(&mut *tx)
        .await
        .unwrap();
        let rows = metadata(&mut tx, owner, "rp").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "current");
        assert!(rows[0].last_used_at.is_none());
        assert!(
            rename::save(&mut tx, owner, "rp", foreign, "Changed".into())
                .await
                .unwrap()
                .is_none()
        );
        let saved = rename::save(&mut tx, owner, "rp", owner, "Renamed".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(saved.name, "Renamed");
    }
}
