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
    read(&state, tx, &raw, None).await
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
    read(&state, tx, &raw, Some(&client)).await
}

async fn read(
    state: &Profile,
    tx: Transaction<'_, Postgres>,
    raw: &str,
    client: Option<&str>,
) -> Response {
    let Ok(chain) = authority(state).await else {
        return internal();
    };
    let user = match crate::query::path_uuid(raw, "user_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    inventory(&state.pool, tx, chain, user, client)
        .await
        .unwrap_or_else(|_| internal())
}

async fn inventory(
    pool: &PgPool,
    mut tx: Transaction<'_, Postgres>,
    chain: Option<crate::chain_settings::Chain>,
    user: Uuid,
    client: Option<&str>,
) -> Result<Response, sqlx::Error> {
    if let Some(chain) = chain {
        let token = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT (SELECT chain_token_id FROM iam_identities WHERE user_id=u.id) FROM users u WHERE u.id=$1",
        ).bind(user).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        let names = match token {
            Some(id) => match chain.membership_names(id).await {
                Ok(names) => Some(names),
                Err(error) => return Ok(chain_error(error)),
            },
            None => None,
        };
        return response(pool, user, client, names).await;
    }
    let names = crate::token_authorization::stored_groups(&mut tx, user).await?;
    response(&mut *tx, user, client, names).await
}

async fn response<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    user: Uuid,
    client: Option<&str>,
    names: Option<Vec<String>>,
) -> Result<Response, sqlx::Error> {
    let Some(names) = names else {
        return Ok(crate::login_http::problem(
            StatusCode::NOT_FOUND,
            "User not found",
        ));
    };
    let Some(client) = client else {
        return Ok(Json(project(user, names)).into_response());
    };
    let roles =
        crate::token_authorization::client_assignments(executor, user, client, &names).await?;
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
