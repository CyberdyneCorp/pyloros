//! Deactivate a UUID-addressed registry entry and publish committed policy.
use super::*;
use crate::grant_response::SessionOrigin;
use std::collections::BTreeSet;

enum Registry {
    Origin,
    Resource,
}

pub(in crate::profile) async fn origin(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    Registry::Origin.handle(&state, peer, &path, &headers).await
}
pub(in crate::profile) async fn resource(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    Registry::Resource
        .handle(&state, peer, &path, &headers)
        .await
}

impl Registry {
    async fn handle(
        &self,
        state: &Profile,
        peer: SocketAddr,
        path: &str,
        headers: &HeaderMap,
    ) -> Response {
        let Some(id) = administrator::identity(state, headers) else {
            return unauthorized();
        };
        let Ok(registry) = catalog(state).await else {
            return internal();
        };
        let (tx, email) = match administrator::session(state, &id).await {
            Ok(session) => session,
            Err(response) => return *response,
        };
        let field = match self {
            Self::Origin => "origin_id",
            Self::Resource => "entry_id",
        };
        let entry = match crate::query::path_uuid(path, field) {
            Ok(entry) => entry,
            Err(issue) => return passkeys::validation(vec![issue]),
        };
        let origin = SessionOrigin {
            ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
            user_agent: crate::token_http::header(headers, "user-agent"),
        };
        self.apply(tx, registry, entry, (id.user, email.as_deref()), origin)
            .await
            .unwrap_or_else(|_| internal())
    }

    async fn apply(
        &self,
        mut tx: Transaction<'static, Postgres>,
        registry: &crate::discovery::ScopeRegistry,
        entry: Uuid,
        actor: (Uuid, Option<&str>),
        origin: SessionOrigin<'_>,
    ) -> Result<Response, sqlx::Error> {
        let Some(kind) = self.mark_inactive(&mut tx, entry).await? else {
            return Ok(problem(
                StatusCode::NOT_FOUND,
                &format!("not found: {entry}"),
            ));
        };
        crate::admin_audit::append(
            &mut tx,
            &format!("{kind}.delete"),
            Some(actor),
            (kind, &entry.to_string()),
            json!({}),
            origin,
        )
        .await?;
        registry.commit(tx).await?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }
    async fn mark_inactive(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        entry: Uuid,
    ) -> Result<Option<&'static str>, sqlx::Error> {
        let (table, column, kind) = match self {
            Self::Origin => (
                "oauth_web_origins",
                "fragment_redirect_uris",
                "oauth_web_origin",
            ),
            Self::Resource => (
                "oauth_protected_resources",
                "scopes",
                "oauth_protected_resource",
            ),
        };
        let raw = sqlx::query_scalar::<_, String>(&format!(
            "SELECT {column} FROM {table} WHERE id=$1 FOR UPDATE"
        ))
        .bind(entry)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(raw) = raw else { return Ok(None) };
        let canonical = raw
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(" ");
        sqlx::query(&format!(
            "UPDATE {table} SET active=false, {column}=$2,
            updated_at=CASE WHEN active OR {column}<>$2 THEN now() ELSE updated_at END WHERE id=$1"
        ))
        .bind(entry)
        .bind(canonical)
        .execute(&mut **tx)
        .await?;
        Ok(Some(kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn deactivating_a_legacy_resource_normalizes_its_persisted_scope_list() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_protected_resources(id uuid, scopes text, active bool, updated_at timestamptz) ON COMMIT DROP")
            .execute(&mut *tx).await.unwrap();
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO oauth_protected_resources VALUES ($1,'view edit view',false,'2000-01-01')",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert_eq!(
            Registry::Resource.mark_inactive(&mut tx, id).await.unwrap(),
            Some("oauth_protected_resource")
        );
        let row: (String, bool) = sqlx::query_as(
            "SELECT scopes,updated_at > '2000-01-01' FROM oauth_protected_resources WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(row, ("edit view".into(), true));
    }
}
