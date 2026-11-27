//! Read the protected-resource inventory directly from the deployment configuration and database.
pub(super) mod write;
use super::*;
use crate::token_runtime::ResourceRegistry;
use std::collections::BTreeSet;

use sqlx::{Row, postgres::PgRow};

const SELECT: &str = "SELECT id,resource,scopes,audience,name,description,active,created_at,updated_at FROM oauth_protected_resources";

fn document(row: PgRow) -> Result<Value, sqlx::Error> {
    let scopes: BTreeSet<_> = row
        .try_get::<&str, _>("scopes")?
        .split_whitespace()
        .collect();
    Ok(json!({
        "id":row.try_get::<Uuid,_>("id")?, "resource":row.try_get::<&str,_>("resource")?,
        "scopes":scopes, "audience":row.try_get::<Option<&str>,_>("audience")?,
        "name":row.try_get::<Option<&str>,_>("name")?, "description":row.try_get::<Option<&str>,_>("description")?,
        "source":"admin", "active":row.try_get::<bool,_>("active")?,
        "created_at":timestamp(row.try_get("created_at")?), "updated_at":timestamp(row.try_get("updated_at")?)
    }))
}

pub(super) async fn list(
    tx: &mut Transaction<'_, Postgres>,
    configured: &ResourceRegistry,
) -> Result<Response, sqlx::Error> {
    let managed = sqlx::query(SELECT)
        .try_map(document)
        .fetch_all(&mut **tx)
        .await?;
    let mut entries: Vec<_> = configured.scopes.iter().map(|(uri, scopes)| json!({
        "id":null, "resource":uri, "scopes":scopes, "audience":configured.audiences.get(uri),
        "name":null, "description":null, "source":"env", "active":true, "created_at":null, "updated_at":null
    })).chain(managed).collect();
    entries.sort_by(|a, b| a["resource"].as_str().cmp(&b["resource"].as_str()));
    Ok(Json(json!({"resources":entries, "total":entries.len()})).into_response())
}

pub(super) async fn get(
    tx: &mut Transaction<'_, Postgres>,
    path: &str,
) -> Result<Response, sqlx::Error> {
    let id = match crate::query::path_uuid(path, "entry_id") {
        Ok(id) => id,
        Err(issue) => {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":[issue]})),
            )
                .into_response());
        }
    };
    let row = sqlx::query(&format!("{SELECT} WHERE id=$1"))
        .bind(id)
        .try_map(document)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(match row {
        Some(row) => Json(row).into_response(),
        None => problem(StatusCode::NOT_FOUND, &format!("not found: {id}")),
    })
}

pub(in crate::profile) async fn deactivate(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(id) = administrator::identity(&state, &headers) else {
        return unauthorized();
    };
    let Ok(registry) = catalog(&state).await else {
        return internal();
    };
    let (tx, email) = match administrator::session(&state, &id).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let entry = match crate::query::path_uuid(&path, "entry_id") {
        Ok(entry) => entry,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = crate::grant_response::SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    deactivate_entry(tx, registry, entry, (id.user, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn deactivate_entry(
    mut tx: Transaction<'static, Postgres>,
    registry: &crate::discovery::ScopeRegistry,
    entry: Uuid,
    actor: (Uuid, Option<&str>),
    origin: crate::grant_response::SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_protected_resources SET active=false,
         updated_at=CASE WHEN active THEN now() ELSE updated_at END WHERE id=$1",
    )
    .bind(entry)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(problem(
            StatusCode::NOT_FOUND,
            &format!("not found: {entry}"),
        ));
    }
    crate::admin_audit::append(
        &mut tx,
        "oauth_protected_resource.delete",
        Some(actor),
        ("oauth_protected_resource", &entry.to_string()),
        json!({}),
        origin,
    )
    .await?;
    registry.commit(tx).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn configured_and_inactive_managed_definitions_share_an_inventory() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_protected_resources (
            id uuid, resource text, scopes text, audience text, name text, description text,
            active boolean, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now()
        ) ON COMMIT DROP").execute(&mut *tx).await.unwrap();
        let id = Uuid::new_v4();
        let uri = "https://service.example";
        sqlx::query("INSERT INTO oauth_protected_resources (id,resource,scopes,active) VALUES ($1,$2,'write read write',false)")
            .bind(id).bind(uri).execute(&mut *tx).await.unwrap();
        let mut configured = ResourceRegistry::default();
        configured
            .scopes
            .insert(uri.into(), BTreeSet::from(["openid".into()]));
        let response = list(&mut tx, &configured).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["total"], 2);
        assert_eq!(doc["resources"][0]["source"], "env");
        let managed = &doc["resources"][1];
        assert_eq!(managed["id"], json!(id));
        assert_eq!(managed["active"], false);
        assert_eq!(managed["scopes"], json!(["read", "write"]));
    }
}
