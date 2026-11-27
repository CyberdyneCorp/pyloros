//! Operator inventory of global roles for an active client.
use super::*;
use crate::chain_settings::SnapshotError;
use axum::extract::Path;
use serde::Serialize;

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(client): Path<String>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    catalog(&state, tx, &client)
        .await
        .unwrap_or_else(|_| internal())
}

async fn catalog(
    state: &Profile,
    mut tx: Transaction<'_, Postgres>,
    client: &str,
) -> Result<Response, sqlx::Error> {
    let chain = state.blockchain.membership_source().await;
    if let Some(source) = &chain {
        source.validate_signer()?;
    }
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM oauth_clients WHERE client_id=$1 AND active)",
    )
    .bind(client)
    .fetch_one(&mut *tx)
    .await?;
    if !active {
        return Ok(admin_permissions::unknown_client(client));
    }
    let groups = if let Some(chain) = chain {
        tx.commit().await?;
        match chain.group_catalog().await {
            Ok(groups) => groups,
            Err(SnapshotError::Deadline) => return Ok(internal()),
            Err(SnapshotError::Unavailable) => {
                return Ok((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                       "type":"about:blank", "title":"Blockchain backend unavailable", "status":503,
                       "detail":"the configured chain RPC endpoint is unreachable or timed out"
                    })),
                )
                    .into_response());
            }
        }
    } else {
        sqlx::query_as(
            "SELECT g.name,g.description,(SELECT count(*) FROM iam_group_members m WHERE m.group_id=g.id)
             FROM iam_groups g WHERE starts_with(g.name,$1) ORDER BY g.name"
        ).bind(format!("rp:{client}:")).fetch_all(&mut *tx).await?
    };
    Ok(Json(json!({"client_id":client,"roles":roles(client, groups)})).into_response())
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
            let (token, org) = crate::token_authorization::assignment(&name)?;
            let (owner, key) = token.rsplit_once(':')?;
            (owner == client && org.is_none()).then(|| Role {
                client_id: client,
                role_key: key.to_owned(),
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
