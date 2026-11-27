//! Operator view of stored user role assignments.
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
    let Ok(chain) = authority(&state).await else {
        return internal();
    };
    let user = match crate::query::path_uuid(&raw, "user_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    inventory(tx, chain, user)
        .await
        .unwrap_or_else(|_| internal())
}

async fn inventory(
    mut tx: Transaction<'_, Postgres>,
    chain: Option<crate::chain_settings::Chain>,
    user: Uuid,
) -> Result<Response, sqlx::Error> {
    let names = if let Some(chain) = chain {
        let token = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT (SELECT chain_token_id FROM iam_identities WHERE user_id=u.id) FROM users u WHERE u.id=$1",
        ).bind(user).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        match token {
            Some(id) => match chain.membership_names(id).await {
                Ok(names) => Some(names),
                Err(error) => return Ok(chain_error(error)),
            },
            None => None,
        }
    } else {
        crate::token_authorization::stored_groups(&mut tx, user).await?
    };
    Ok(match names {
        Some(names) => Json(project(user, names)).into_response(),
        None => crate::login_http::problem(StatusCode::NOT_FOUND, "User not found"),
    })
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
