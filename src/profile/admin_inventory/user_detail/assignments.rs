//! Project the IAM detail for a single user from the selected provider.
use super::*;
fn empty() -> Value {
    json!({"identity":null,"policies":[],"groups":[],"roles":[],"boundary_policy":null})
}

pub(super) async fn remote(
    mut tx: Transaction<'_, Postgres>,
    chain: &Chain,
    user: Uuid,
) -> Result<Response, sqlx::Error> {
    let record = sqlx::query_as::<_, (Option<i32>, String, String)>(
        "SELECT chain_token_id,status,transfer_mode FROM iam_identities WHERE user_id=$1",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    if let Some((token, status, mode)) = record {
        group_members::validate_identity(&status, &mode)?;
        if token.is_some()
            && let Err(error) = chain.check_user_catalog().await
        {
            return Ok(admin_client_roles::chain_error(error));
        }
    }
    Ok(Json(empty()).into_response())
}

pub(super) async fn postgres(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Value, sqlx::Error> {
    let row=sqlx::query_as::<_,(Uuid,Value,DateTime<Utc>,String,String)>(
        "SELECT id,jsonb_build_object('id',id,'chain_token_id',chain_token_id,'user_id',user_id,
            'owner_address',owner_address,'public_key',public_key,'email',email,'metadata_uri',metadata_uri),
            created_at,status,transfer_mode FROM iam_identities WHERE user_id=$1"
    ).bind(user).fetch_optional(&mut **tx).await?;
    let Some((id, mut identity, created, status, mode)) = row else {
        return Ok(empty());
    };
    group_members::validate_identity(&status, &mode)?;
    identity["status"] = json!(status);
    identity["transfer_mode"] = json!(mode);
    identity["created_at"] = json!(timestamp(created));
    let mut doc = empty();
    doc["identity"] = identity;
    doc["groups"]=json!(dated(sqlx::query_as(
        "SELECT jsonb_build_object('id',g.id,'name',g.name,'description',g.description,'is_active',g.is_active,
         'chain_group_id',g.chain_group_id,'policy_ids','[]'::jsonb,'member_count',(SELECT count(*) FROM iam_group_members m WHERE m.group_id=g.id)),g.created_at
         FROM iam_group_members m JOIN iam_groups g ON g.id=m.group_id WHERE m.identity_id=$1"
    ).bind(id).fetch_all(&mut **tx).await?));
    doc["roles"]=json!(dated(sqlx::query_as(
        "SELECT jsonb_build_object('id',r.id,'name',r.name,'description',r.description,'max_session_duration_s',r.max_session_duration_s,
         'is_active',r.is_active,'chain_role_id',r.chain_role_id),r.created_at
         FROM iam_role_sessions s JOIN iam_roles r ON r.id=s.role_id WHERE s.identity_id=$1 AND s.active AND s.expiry_at>statement_timestamp()"
    ).bind(id).fetch_all(&mut **tx).await?));
    let links = sqlx::query_as::<_, (Uuid, bool)>(
        "SELECT policy_id,false FROM iam_identity_policies WHERE identity_id=$1
        UNION ALL SELECT policy_id,true FROM iam_permission_boundaries WHERE identity_id=$1",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    let ids: Vec<_> = links.iter().map(|(id, _)| *id).collect();
    let mut policies = statements::load(tx, Some(&ids))
        .await?
        .into_iter()
        .peekable();
    let mut direct = Vec::new();
    for (id, boundary) in links {
        // A concurrently deleted policy can disappear between reads.
        if policies.peek().is_some_and(|p| p["id"] == id.to_string()) {
            let value = policies.next().expect("peeked policy");
            if boundary {
                doc["boundary_policy"] = value;
            } else {
                direct.push(value);
            }
        }
    }
    doc["policies"] = Value::Array(direct);
    Ok(doc)
}
