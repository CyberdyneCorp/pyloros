//! Reconcile a read-only chain snapshot with the PostgreSQL IAM store.
use super::*;
use crate::{chain_settings::Inventory, grant_response::SessionOrigin, login_http::problem};
use alloy_primitives::U256;
use std::collections::HashMap;

pub(in crate::profile) async fn run(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(record) => record,
        Err(error) => return *error,
    };
    let Some(chain) = state.blockchain.provider().await else {
        return problem(StatusCode::BAD_REQUEST, "blockchain not configured");
    };
    if chain.validate_signer().is_err() {
        return internal();
    }
    let snapshot = match chain.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => return admin_client_roles::chain_error(error),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    apply(tx, snapshot, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

fn chain_id(id: U256) -> Result<i32, sqlx::Error> {
    i32::try_from(id).map_err(|_| {
        sqlx::Error::Decode("chain identifier exceeds PostgreSQL integer range".into())
    })
}

async fn apply(
    mut tx: Transaction<'_, Postgres>,
    snapshot: Inventory,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let policy_count = snapshot.policies.len();
    let group_count = snapshot.groups.len();
    let mut ids = HashMap::with_capacity(policy_count);
    for policy in snapshot.policies {
        let id = store_policy(
            &mut tx,
            chain_id(policy.id)?,
            &policy.name,
            &policy.description,
        )
        .await?;
        ids.insert(policy.id, id);
    }
    for group in snapshot.groups {
        let id = store_group(
            &mut tx,
            chain_id(group.id)?,
            &group.name,
            &group.description,
        )
        .await?;
        for remote in group.policy_ids {
            if let Some(policy) = ids.get(&remote) {
                attach(&mut tx, id, *policy).await?;
            }
        }
    }
    crate::admin_audit::append_record(
        &mut tx,
        "iam.import",
        Some(actor),
        Some(("iam", None)),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"policies":policy_count,"groups":group_count,"roles":0,"identities":0,
        "boundaries":0,"gaps":[],"policies_statements_skipped":policy_count}),
    )
    .into_response())
}

async fn store_policy(
    tx: &mut Transaction<'_, Postgres>,
    remote: i32,
    name: &str,
    description: &str,
) -> Result<Uuid, sqlx::Error> {
    let existing = sqlx::query_as::<_, (Uuid, i32)>(
        "SELECT id,version FROM iam_policies WHERE chain_policy_id=$1",
    )
    .bind(remote)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((id, version)) = existing else {
        return sqlx::query_scalar("INSERT INTO iam_policies(id,chain_policy_id,name,description) VALUES(gen_random_uuid(),$1,$2,$3) RETURNING id")
            .bind(remote).bind(name).bind(description).fetch_one(&mut **tx).await;
    };
    statements::refresh_imported_rules(tx, id).await?;
    sqlx::query("UPDATE iam_policies SET name=$2,description=$3,version=$4::integer+1,updated_at=now() WHERE id=$1")
        .bind(id).bind(name).bind(description).bind(version).execute(&mut **tx).await?;
    Ok(id)
}

async fn store_group(
    tx: &mut Transaction<'_, Postgres>,
    remote: i32,
    name: &str,
    description: &str,
) -> Result<Uuid, sqlx::Error> {
    let existing =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_groups WHERE chain_group_id=$1")
            .bind(remote)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(id) = existing else {
        return sqlx::query_scalar("INSERT INTO iam_groups(id,chain_group_id,name,description) VALUES(gen_random_uuid(),$1,$2,$3) RETURNING id")
            .bind(remote).bind(name).bind(description).fetch_one(&mut **tx).await;
    };
    sqlx::query("UPDATE iam_groups SET name=$2,description=$3,updated_at=now() WHERE id=$1 AND (name,description) IS DISTINCT FROM ($2,$3)")
        .bind(id).bind(name).bind(description).execute(&mut **tx).await?;
    Ok(id)
}

async fn attach(
    tx: &mut Transaction<'_, Postgres>,
    group: Uuid,
    policy: Uuid,
) -> Result<(), sqlx::Error> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM iam_group_policies WHERE group_id=$1 AND policy_id=$2)",
    )
    .bind(group)
    .bind(policy)
    .fetch_one(&mut **tx)
    .await?;
    if !exists {
        sqlx::query("INSERT INTO iam_group_policies(group_id,policy_id) VALUES($1,$2)")
            .bind(group)
            .bind(policy)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}
