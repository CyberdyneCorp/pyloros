//! Operator IAM inventories from the selected IAM provider.
use super::*;
use serde::Serialize;

mod statements;

#[derive(Clone, Copy)]
enum Catalog {
    Groups,
    Policies,
    Roles,
}

fn response<T: Serialize>(key: &'static str, entries: Vec<T>) -> Response {
    // Serialize entries directly to preserve chain identifiers wider than u64.
    #[derive(Serialize)]
    struct Inventory<T> {
        #[serde(flatten)]
        entries: std::collections::BTreeMap<&'static str, Vec<T>>,
        total: usize,
    }
    let total = entries.len();
    Json(Inventory {
        entries: std::collections::BTreeMap::from([(key, entries)]),
        total,
    })
    .into_response()
}

pub(super) async fn groups(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    list(&state, method, &headers, Catalog::Groups).await
}
pub(super) async fn policies(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    list(&state, method, &headers, Catalog::Policies).await
}
pub(super) async fn roles(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    list(&state, method, &headers, Catalog::Roles).await
}
async fn list(state: &Profile, method: Method, headers: &HeaderMap, catalog: Catalog) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(state, headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    match admin_client_roles::authority(state).await {
        Err(_) => internal(),
        Ok(Some(chain)) => {
            if tx.commit().await.is_err() {
                return internal();
            }
            let result = match catalog {
                Catalog::Groups => chain
                    .operator_groups()
                    .await
                    .map(|rows| response("groups", rows)),
                Catalog::Policies => chain
                    .operator_policies()
                    .await
                    .map(|rows| response("policies", rows)),
                Catalog::Roles => chain
                    .operator_roles()
                    .await
                    .map(|rows| response("roles", rows)),
            };
            result.unwrap_or_else(admin_client_roles::chain_error)
        }
        Ok(None) => {
            let (key, rows) = match catalog {
                Catalog::Groups => ("groups", postgres_groups(&mut tx).await),
                Catalog::Policies => ("policies", statements::policies(&mut tx).await),
                Catalog::Roles => ("roles", postgres_roles(&mut tx).await),
            };
            rows.map(|items| response(key, items))
                .unwrap_or_else(|_| internal())
        }
    }
}

async fn postgres_roles(tx: &mut Transaction<'_, Postgres>) -> Result<Vec<Value>, sqlx::Error> {
    let rows=sqlx::query_as::<_,(Value,DateTime<Utc>)>(
        "SELECT jsonb_build_object('id',id,'name',name,'description',description,'is_active',is_active,
         'chain_role_id',chain_role_id,'max_session_duration_s',max_session_duration_s),created_at FROM iam_roles ORDER BY name"
    ).fetch_all(&mut **tx).await?;
    Ok(dated(rows))
}

async fn postgres_groups(tx: &mut Transaction<'_, Postgres>) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query_as::<_,(Value,DateTime<Utc>)>(
        "SELECT jsonb_build_object('id',g.id,'name',g.name,'description',g.description,
                'is_active',g.is_active,'chain_group_id',g.chain_group_id,
                'member_count',(SELECT count(*) FROM iam_group_members m WHERE m.group_id=g.id),
                'policy_ids',ARRAY(SELECT p.policy_id FROM iam_group_policies p WHERE p.group_id=g.id)),
                g.created_at FROM iam_groups g ORDER BY g.name"
    ).fetch_all(&mut **tx).await?;
    Ok(dated(rows))
}

fn dated(rows: Vec<(Value, DateTime<Utc>)>) -> Vec<Value> {
    rows.into_iter()
        .map(|(mut item, created)| {
            item["created_at"] = json!(timestamp(created));
            item
        })
        .collect()
}
