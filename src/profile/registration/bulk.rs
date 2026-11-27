//! Transactional CSV import for administrative account provisioning.
mod csv_input;
mod input;
use super::admin::{Creation, Operator, create_verified};
use super::*;
use std::collections::HashSet;

pub(in crate::profile) async fn handle(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() == Method::DELETE {
        return erasure::remove(
            State(state),
            ConnectInfo(peer),
            req.headers().clone(),
            axum::extract::Path("bulk".into()),
        )
        .await;
    }
    if req.method() == Method::GET {
        return admin_users::detail(
            State(state),
            Method::GET,
            req.headers().clone(),
            axum::extract::Path("bulk".into()),
        )
        .await;
    }
    if req.method() != Method::POST {
        let mut r = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        r.headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return r;
    }
    let headers = req.headers().clone();
    let upload = match input::envelope(req).await {
        Ok(u) => u,
        Err(r) => return *r,
    };
    let (tx, id, email) = match administrator::operator(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let records = match input::records(upload).await {
        Ok(rows) => rows,
        Err(r) => return *r,
    };
    let operator = Operator {
        id,
        origin: SessionOrigin {
            ip: client_ip(&headers, peer.ip(), state.proxies),
            user_agent: value(&headers, "user-agent"),
        },
        request: value(&headers, "x-request-id"),
    };
    import(tx, &state, records, operator, email.as_deref())
        .await
        .unwrap_or_else(|_| internal())
}

fn row_error(email: &str, password: &str) -> Option<&'static str> {
    if email.is_empty() {
        Some("missing email")
    } else if crate::login_http::email_field(&json!({"email":email})).is_err() {
        Some("invalid email")
    } else if !(8..=128).contains(&password.chars().count()) {
        Some("password must be between 8 and 128 characters")
    } else if !password_change::valid_password(password) {
        Some("password must contain lower, upper, digit, and non-alphanumeric characters")
    } else {
        None
    }
}

fn failed(row: usize, email: &str, error: &str) -> Value {
    json!({"row":row,"email":(!email.is_empty()).then_some(email),"status":"failed","user_id":null,"error":error})
}
async fn import(
    mut tx: Transaction<'_, Postgres>,
    state: &Profile,
    records: Vec<(String, String)>,
    operator: Operator<'_>,
    actor_email: Option<&str>,
) -> Result<Response, Box<dyn Error + Send + Sync>> {
    let total = records.len();
    let mut results = Vec::with_capacity(total);
    let mut seen = HashSet::new();
    let mut created = 0;
    for (i, (raw, password)) in records.into_iter().enumerate() {
        let row = i + 2;
        if let Some(error) = row_error(&raw, &password) {
            results.push(failed(row, &raw, error));
            continue;
        }
        let email = raw.to_lowercase();
        if !seen.insert(email.clone()) {
            results.push(failed(row, &email, "duplicate email in file"));
            continue;
        }
        let result =
            match create_verified(&mut tx, state, &email, password, &operator, Some(row)).await? {
                Creation::Created(id, _) => {
                    created += 1;
                    json!({"row":row,"email":email,"status":"created","user_id":id,"error":null})
                }
                Creation::Existing => failed(row, &email, "email already registered"),
                Creation::ConcurrentDuplicate => return Ok(internal()),
                Creation::Unavailable(message) => {
                    return Ok(problem(StatusCode::SERVICE_UNAVAILABLE, message));
                }
            };
        results.push(result);
    }
    let mut summary = json!({"total":total,"created":created,"failed":total-created});
    crate::admin_audit::append_record(
        &mut tx,
        "user.bulk_import",
        Some((operator.id, actor_email)),
        None,
        summary.clone(),
        operator.origin,
    )
    .await?;
    tx.commit().await?;
    summary["results"] = json!(results);
    Ok(Json(summary).into_response())
}
