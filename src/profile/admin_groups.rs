//! Operator group inventory from the selected IAM provider.
use super::*;
use serde::Serialize;

#[derive(Serialize)]
struct Inventory<T> {
    groups: Vec<T>,
    total: usize,
}

fn response<T: Serialize>(groups: Vec<T>) -> Response {
    Json(Inventory {
        total: groups.len(),
        groups,
    })
    .into_response()
}

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    match admin_client_roles::authority(&state).await {
        Err(_) => internal(),
        Ok(Some(chain)) => {
            if tx.commit().await.is_err() {
                return internal();
            }
            match chain.operator_groups().await {
                Ok(groups) => response(groups),
                Err(error) => admin_client_roles::chain_error(error),
            }
        }
        Ok(None) => match postgres_groups(&mut tx).await {
            Ok(groups) => response(groups),
            Err(_) => internal(),
        },
    }
}

async fn postgres_groups(tx: &mut Transaction<'_, Postgres>) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query_as::<_,(Value,DateTime<Utc>)>(
        "SELECT jsonb_build_object('id',g.id,'name',g.name,'description',g.description,
                'is_active',g.is_active,'chain_group_id',g.chain_group_id,
                'member_count',(SELECT count(*) FROM iam_group_members m WHERE m.group_id=g.id),
                'policy_ids',ARRAY(SELECT p.policy_id FROM iam_group_policies p WHERE p.group_id=g.id)),
                g.created_at FROM iam_groups g ORDER BY g.name"
    ).fetch_all(&mut **tx).await?;
    Ok(rows
        .into_iter()
        .map(|(mut group, created)| {
            group["created_at"] = json!(timestamp(created));
            group
        })
        .collect())
}
