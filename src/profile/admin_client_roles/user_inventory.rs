//! Operator and service-client views of a user’s role assignments.
use super::*;
use std::collections::BTreeMap;

pub(in crate::profile) async fn list_user(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    read(&state, tx, &raw, View::Inventory).await
}

pub(in crate::profile) async fn delegated_user(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let client = match delegated::client(&state, &headers).await {
        Ok(client) => client,
        Err(error) => return *error,
    };
    let Ok(tx) = state.pool.begin().await else {
        return internal();
    };
    read(&state, tx, &raw, View::Roles(Some(&client))).await
}

enum View<'a> {
    Inventory,
    Roles(Option<&'a str>),
    Permissions(&'a str),
}

pub(in crate::profile) async fn claims<const PERMISSIONS: bool>(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    use crate::login_http::problem;
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, owner) = match delegated::read_caller(&state, &headers, "roles:read").await {
        Ok(result) => result,
        Err(error) => return *error,
    };
    let Ok(chain) = authority(&state).await else {
        return internal();
    };
    let user = match crate::query::path_uuid(&raw, "user_id") {
        Ok(user) => user,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let requested = url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == "client_id")
        .map(|(_, value)| value)
        .last();
    if let (Some(caller), Some(selected)) = (owner.as_deref(), requested.as_deref())
        && caller != selected
    {
        let resource = if PERMISSIONS { "permissions" } else { "roles" };
        return problem(
            StatusCode::FORBIDDEN,
            &format!("service tokens may only read their own client's {resource}"),
        );
    }
    let client = owner.as_deref().or(requested.as_deref());
    let view = if PERMISSIONS {
        let Some(client) = client else {
            return problem(
                StatusCode::BAD_REQUEST,
                "client_id query parameter is required",
            );
        };
        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT FROM oauth_clients WHERE client_id=$1 AND active)",
        )
        .bind(client)
        .fetch_one(&mut *tx)
        .await
        {
            Ok(true) => View::Permissions(client),
            Ok(false) => return admin_permissions::unknown_client(client),
            Err(_) => return internal(),
        }
    } else {
        View::Roles(client)
    };
    inventory(&state.pool, tx, chain, user, view)
        .await
        .unwrap_or_else(|_| internal())
}

async fn validate_user(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<bool, sqlx::Error> {
    let metadata: Option<String> =
        sqlx::query_scalar("SELECT extra_metadata::text FROM users WHERE id=$1")
            .bind(user)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(metadata) = metadata else {
        return Ok(false);
    };
    admin_organizations::normalized_storage(&metadata)?;
    Ok(true)
}

async fn read(
    state: &Profile,
    tx: Transaction<'_, Postgres>,
    raw: &str,
    view: View<'_>,
) -> Response {
    let Ok(chain) = authority(state).await else {
        return internal();
    };
    let user = match crate::query::path_uuid(raw, "user_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    inventory(&state.pool, tx, chain, user, view)
        .await
        .unwrap_or_else(|_| internal())
}

async fn inventory(
    pool: &PgPool,
    mut tx: Transaction<'_, Postgres>,
    chain: Option<crate::chain_settings::Chain>,
    user: Uuid,
    view: View<'_>,
) -> Result<Response, sqlx::Error> {
    if !validate_user(&mut tx, user).await? {
        return Ok(crate::login_http::problem(
            StatusCode::NOT_FOUND,
            "User not found",
        ));
    }
    let (names, mut storage) = if let Some(chain) = chain {
        let token = admin_inventory::linked_token(&mut tx, user).await?;
        tx.commit().await?;
        match chain.membership_names(token).await {
            Ok(names) => (names, None),
            Err(error) => return Ok(chain_error(error)),
        }
    } else {
        let names = admin_inventory::group_names(&mut tx, user).await?;
        (names, Some(tx))
    };
    let client = match view {
        View::Inventory => return Ok(Json(project(user, names)).into_response()),
        View::Roles(client) => client,
        View::Permissions(client) => {
            let mut acquired;
            let conn = match storage.as_mut() {
                Some(tx) => &mut **tx,
                None => {
                    acquired = pool.acquire().await?;
                    &mut *acquired
                }
            };
            let perms =
                crate::token_authorization::client_permissions(conn, user, &names, client).await?;
            return Ok(Json(
                json!({"permissions":perms.global,"org_permissions":perms.organizations}),
            )
            .into_response());
        }
    };
    use crate::token_authorization::role_assignments;
    let roles = match storage.as_mut() {
        Some(tx) => role_assignments(&mut **tx, user, client, &names).await?,
        None => role_assignments(pool, user, client, &names).await?,
    };
    let mut doc = json!({"user_id":user,"roles":roles.global});
    if !roles.organizations.is_empty() {
        doc["org_roles"] = json!(roles.organizations);
    }
    Ok(Json(doc).into_response())
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Entry {
    client_id: String,
    role_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<Uuid>,
}

#[derive(Serialize)]
struct Inventory {
    user_id: Uuid,
    roles: Vec<Entry>,
    org_roles: BTreeMap<Uuid, Vec<Entry>>,
}

fn project(user_id: Uuid, names: Vec<String>) -> Inventory {
    let mut entries: Vec<_> = names
        .iter()
        .filter_map(|name| {
            let (token, organization_id) = crate::token_authorization::assignment(name)?;
            let (client, key) = token.rsplit_once(':')?;
            Some(Entry {
                client_id: client.to_owned(),
                role_key: key.to_owned(),
                organization_id,
            })
        })
        .collect();
    entries.sort_unstable();
    let mut inventory = Inventory {
        user_id,
        roles: Vec::new(),
        org_roles: BTreeMap::new(),
    };
    for entry in entries {
        match entry.organization_id {
            Some(org) => inventory.org_roles.entry(org).or_default().push(entry),
            None => inventory.roles.push(entry),
        }
    }
    inventory
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_preserves_duplicates_and_separates_org_assignments() {
        let id = Uuid::new_v4();
        let org = Uuid::new_v4();
        let names = vec![
            "rp:z:read".into(),
            "rp:a:staff".into(),
            "rp:a:staff".into(),
            format!("rp:a:staff@{org}"),
            "rp:a:staff@invalid".into(),
        ];
        let inventory = serde_json::to_value(project(id, names)).unwrap();
        let global = json!({"client_id":"a","role_key":"staff"});
        assert_eq!(
            inventory["roles"],
            json!([global,global,{"client_id":"z","role_key":"read"}])
        );
        assert_eq!(
            inventory["org_roles"][org.to_string()],
            json!([{"client_id":"a","role_key":"staff","organization_id":org}])
        );
    }
}
