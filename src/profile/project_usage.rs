//! Administrative reporting on project sign-ins and access grants.
use super::*;
use crate::login_http::problem;
use axum::extract::{Path, RawQuery};
use std::collections::HashMap;
type Tx<'a> = Transaction<'a, Postgres>;
mod overview;
mod participants;
mod registry;

pub(super) fn routes() -> Router<Arc<Profile>> {
    Router::new()
        .route("/api/v1/admin/projects", any(read))
        .route("/api/v1/admin/projects/{client_id}/users", any(read))
        .route("/api/v1/admin/users/{user_id}/projects", any(read))
}

async fn read(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(path): Path<HashMap<String, String>>,
    RawQuery(raw): RawQuery,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(error) => return *error,
    };
    let result = if let Some(id) = path.get("user_id") {
        let user = match crate::query::path_uuid(id, "user_id") {
            Ok(user) => user,
            Err(error) => return passkeys::validation(vec![error]),
        };
        participants::projects(&mut tx, user).await
    } else {
        let params =
            url::form_urlencoded::parse(raw.as_deref().unwrap_or_default().as_bytes()).collect();
        let mut issues = Vec::new();
        let (number, size) = crate::query::pagination(&params, 50, 200, &mut issues);
        if !issues.is_empty() {
            return passkeys::validation(issues);
        }
        let page = Page { number, size };
        match path.get("client_id") {
            Some(id) => participants::members(&mut tx, id, page).await,
            None => overview::list(&mut tx, page).await,
        }
    };
    result.unwrap_or_else(|_| internal())
}

struct Page {
    number: i128,
    size: i64,
}
impl Page {
    fn offset(&self) -> sqlx::Result<i64> {
        (self.number - 1)
            .checked_mul(self.size.into())
            .and_then(|n| i64::try_from(n).ok())
            .ok_or_else(|| sqlx::Error::Protocol("page offset exceeds database range".into()))
    }
}
fn stamp(bytes: &[u8]) -> sqlx::Result<String> {
    Ok(event_time::EventTime::decode(bytes)?.display("Z"))
}
