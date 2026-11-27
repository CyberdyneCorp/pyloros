//! Operator inventory of global roles for an active client.
use super::*;
mod creation;
mod grant;
mod revoke;
pub(super) use grant::grant;
pub(super) use revoke::revoke;
mod user_inventory;
pub(super) use user_inventory::list_user;
mod removal;
mod replacement;
use crate::chain_settings::SnapshotError;
use axum::extract::Path;
pub(super) use creation::create;
pub(super) use removal::remove;
pub(super) use replacement::put;
use serde::Serialize;

struct Assignment {
    user: Uuid,
    client: String,
    key: String,
    org: Option<Uuid>,
}

impl Assignment {
    fn metadata(&self) -> Value {
        let mut item = json!({"client_id":self.client,"role_key":self.key});
        if let Some(org) = self.org {
            item["organization_id"] = json!(org);
        }
        item
    }

    async fn check_target(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<Response>, sqlx::Error> {
        use crate::login_http::problem;
        if sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR NO KEY UPDATE")
            .bind(self.user)
            .fetch_optional(&mut **tx)
            .await?
            .is_none()
        {
            return Ok(Some(problem(StatusCode::NOT_FOUND, "User not found")));
        }
        if !active_client_for_update(tx, &self.client).await? {
            return Ok(Some(admin_permissions::unknown_client(&self.client)));
        }
        if !crate::token_authorization::valid_role_key(&self.key) {
            return Ok(Some(problem(
                StatusCode::BAD_REQUEST,
                &format!(
                    "invalid role_key {}: must match [a-z0-9][a-z0-9_-]{{0,47}}",
                    crate::browser_prompt::quoted_string(&self.key)
                ),
            )));
        }
        Ok(None)
    }
}

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(client): Path<String>,
) -> Response {
    read(&state, method, &headers, &client, None).await
}

pub(super) async fn mapping(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path((client, role)): Path<(String, String)>,
) -> Response {
    read(&state, method, &headers, &client, Some(&role)).await
}

async fn read(
    state: &Profile,
    method: Method,
    headers: &HeaderMap,
    client: &str,
    role: Option<&str>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (tx, _, _) = match administrator::operator(state, headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Ok(chain) = authority(state).await else {
        return internal();
    };
    catalog(
        state,
        chain,
        tx,
        client,
        role.map(|key| Target { key, change: None }),
    )
    .await
    .unwrap_or_else(|_| internal())
}

struct Target<'a> {
    key: &'a str,
    change: Option<replacement::Change<'a>>,
}

async fn authority(state: &Profile) -> Result<Option<crate::chain_settings::Chain>, sqlx::Error> {
    let chain = state.blockchain.membership_source().await;
    if let Some(source) = &chain {
        source.validate_signer()?;
    }
    Ok(chain)
}

async fn catalog(
    state: &Profile,
    chain: Option<crate::chain_settings::Chain>,
    mut tx: Transaction<'_, Postgres>,
    client: &str,
    target: Option<Target<'_>>,
) -> Result<Response, sqlx::Error> {
    let role = target.as_ref().map(|t| t.key);
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM oauth_clients WHERE client_id=$1 AND active)",
    )
    .bind(client)
    .fetch_one(&mut *tx)
    .await?;
    if !active {
        return Ok(admin_permissions::unknown_client(client));
    }
    if let Some(key) = role
        && !crate::token_authorization::valid_role_key(key)
    {
        let key = crate::browser_prompt::quoted_string(key);
        return Ok(crate::login_http::problem(
            StatusCode::BAD_REQUEST,
            &format!("invalid role_key {key}: must match [a-z0-9][a-z0-9_-]{{0,47}}"),
        ));
    }
    if chain.is_none()
        && let Some(target) = target
    {
        let key = target.key;
        if target.change.is_some() {
            lock_role(&mut tx, client, key).await?;
        }
        let name = format!("rp:{client}:{key}");
        let exists = !client.contains('@')
            && sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT FROM iam_groups WHERE name=$1)")
                .bind(name)
                .fetch_one(&mut *tx)
                .await?;
        return complete_mapping(tx, client, target, exists).await;
    }
    let groups = if let Some(chain) = chain {
        tx.commit().await?;
        match chain.group_catalog().await {
            Ok(groups) => groups,
            Err(error) => return Ok(chain_error(error)),
        }
    } else {
        sqlx::query_as(
            "SELECT g.name,g.description,(SELECT count(*) FROM iam_group_members m WHERE m.group_id=g.id)
             FROM iam_groups g WHERE starts_with(g.name,$1) ORDER BY g.name"
        ).bind(format!("rp:{client}:")).fetch_all(&mut *tx).await?
    };
    let roles = roles(client, groups);
    match target {
        None => Ok(Json(json!({"client_id":client,"roles":roles})).into_response()),
        Some(target) => {
            let exists = roles.iter().any(|r| r.role_key == target.key);
            let mut tx = state.pool.begin().await?;
            if target.change.is_some() {
                lock_role(&mut tx, client, target.key).await?;
            }
            complete_mapping(tx, client, target, exists).await
        }
    }
}

fn chain_error(error: SnapshotError) -> Response {
    match error {
        SnapshotError::Deadline => internal(),
        SnapshotError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "type":"about:blank", "title":"Blockchain backend unavailable", "status":503,
                "detail":"the configured chain RPC endpoint is unreachable or timed out"
            })),
        )
            .into_response(),
    }
}

fn global_key(client: &str, name: &str) -> Option<String> {
    let (token, org) = crate::token_authorization::assignment(name)?;
    let (owner, key) = token.rsplit_once(':')?;
    (owner == client && org.is_none()).then(|| key.to_owned())
}

async fn complete_mapping(
    mut tx: Transaction<'_, Postgres>,
    client: &str,
    target: Target<'_>,
    exists: bool,
) -> Result<Response, sqlx::Error> {
    match target.change {
        Some(change) if exists => change.apply(tx, client, target.key).await,
        _ => role_mapping(&mut *tx, client, target.key, exists).await,
    }
}

fn missing_role(client: &str, key: &str) -> Response {
    use crate::browser_prompt::quoted_string;
    crate::login_http::problem(
        StatusCode::NOT_FOUND,
        &format!(
            "role {} not found for client {}",
            quoted_string(key),
            quoted_string(client)
        ),
    )
}

async fn lock_role(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
    key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))")
        .bind(client)
        .bind(key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn active_client_for_update(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
) -> Result<bool, sqlx::Error> {
    let active = sqlx::query_scalar::<_, bool>(
        "SELECT active FROM oauth_clients WHERE client_id=$1 FOR NO KEY UPDATE",
    )
    .bind(client)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(active == Some(true))
}

async fn role_mapping<'a>(
    db: impl sqlx::PgExecutor<'a>,
    client: &str,
    key: &str,
    exists: bool,
) -> Result<Response, sqlx::Error> {
    if !exists {
        return Ok(missing_role(client, key));
    }
    let permissions: Vec<String> = sqlx::query_scalar(
        r#"SELECT permission_key FROM client_role_permissions
           WHERE client_id=$1 AND role_key=$2 ORDER BY permission_key COLLATE "C""#,
    )
    .bind(client)
    .bind(key)
    .fetch_all(db)
    .await?;
    Ok(Json(json!({"client_id":client,"role_key":key,"permissions":permissions})).into_response())
}

#[derive(Serialize)]
struct Role<'a> {
    client_id: &'a str,
    role_key: String,
    description: Option<String>,
    member_count: i64,
}

fn roles(client: &str, groups: Vec<(String, Option<String>, i64)>) -> Vec<Role<'_>> {
    let mut roles: Vec<_> = groups
        .into_iter()
        .filter_map(|(name, description, member_count)| {
            Some(Role {
                client_id: client,
                role_key: global_key(client, &name)?,
                description,
                member_count,
            })
        })
        .collect();
    roles.sort_by(|a, b| a.role_key.cmp(&b.role_key));
    roles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn mapping_is_sorted_and_scoped_to_an_existing_role() {
        let db = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = db.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE client_role_permissions(client_id text, role_key text, permission_key text);
            INSERT INTO client_role_permissions VALUES ('a','reader','view'),('a','reader','export'),('b','reader','manage'),('a','owner','manage');")
            .execute(&mut *tx).await.unwrap();
        let response = role_mapping(&mut *tx, "a", "reader", true).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"client_id":"a","role_key":"reader","permissions":["export","view"]})
        );
        assert_eq!(
            role_mapping(&mut *tx, "a", "reader", false)
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn catalog_projects_only_global_roles_owned_by_the_requested_client() {
        let groups = [
            ("rp:app:other:owner", 2),
            ("rp:app:viewer", 0),
            ("rp:app:reader@5a35f9ef-cdc8-46c7-bde2-9c0bc1771758", 1),
            ("rp:app:reader\n", 3),
            ("rp:app:reader\n\n", 4),
        ]
        .map(|(name, count)| (name.to_owned(), None, count))
        .to_vec();
        let entries = roles("app", groups);
        let keys: Vec<_> = entries
            .iter()
            .map(|r| (r.role_key.as_str(), r.member_count))
            .collect();
        assert_eq!(keys, [("reader\n", 3), ("viewer", 0)]);
    }
}
