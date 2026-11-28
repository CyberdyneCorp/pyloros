//! Store ordered policy statements and their operator audit atomically.
use super::*;
use crate::chain_settings::{Chain, IamMutation, PrepareError};
use crate::{grant_response::SessionOrigin, request_json::iam_document};

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    write(&state, peer, &headers, &bytes, None).await
}

pub(in crate::profile) async fn replace(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(path): axum::extract::Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    write(&state, peer, &headers, &bytes, Some(&path)).await
}

async fn write(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    bytes: &[u8],
    path: Option<&str>,
) -> Response {
    let raw = match iam_document::document(headers, bytes) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (tx, actor, email) = match administrator::operator(state, headers).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Ok(chain) = admin_client_roles::authority(state).await else {
        return internal();
    };
    let Some(raw) = raw else {
        return internal();
    };
    let path = path.map(|raw| crate::query::path_uuid(raw, "policy_id"));
    let (id, policy) = match input::parse(&raw, path) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Some(chain) = chain {
        let mutation = match id {
            Some(id) => IamMutation::ReplacePolicy(id, &policy),
            None => IamMutation::CreatePolicy(&policy),
        };
        return prepare_chain_write(tx, &chain, mutation).await;
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    store(tx, id, &policy, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

pub(super) async fn prepare_chain_write(
    mut tx: Transaction<'_, Postgres>,
    chain: &Chain,
    mutation: IamMutation<'_>,
) -> Response {
    if chain.lock_signer(&mut tx).await.is_err() {
        return internal();
    }
    let response = match chain.prepare_mutation(&mutation).await {
        Ok(_) => crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Blockchain transaction submission unavailable",
        ),
        Err(error) => preparation_error(&mutation, error),
    };
    if tx.commit().await.is_err() {
        return internal();
    }
    response
}

pub(super) fn preparation_error(mutation: &IamMutation<'_>, error: PrepareError) -> Response {
    match error {
        PrepareError::MissingGroup(_) | PrepareError::MissingPolicy(_)
            if matches!(mutation, IamMutation::GroupPolicy { attach: false, .. }) => internal(),
        PrepareError::MissingIdentity(_) if matches!(mutation,IamMutation::Boundary{policy:None,..})=>internal(),
        PrepareError::MissingIdentity(id)=>crate::login_http::problem(StatusCode::NOT_FOUND,&id.to_string()),
        PrepareError::MissingGroup(id) => delete_group::missing(id),
        PrepareError::MissingPolicy(id) => missing(id),
        PrepareError::AttachedPolicy(id) => removal::attached(id),
        PrepareError::ProtectedGroup => delete_group::protected(),
        PrepareError::Catalog(error) => admin_client_roles::chain_error(error),
        PrepareError::Invalid | PrepareError::Argument(_) => internal(),
        PrepareError::Unavailable | PrepareError::Rpc(_) | PrepareError::Reverted(_) if matches!(mutation, IamMutation::CreatePolicy(_)) => internal(),
        PrepareError::Reverted(detail) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"status":502, "type":"about:blank", "title":"Chain transaction failed", "detail":detail})),
        ).into_response(),
        PrepareError::Unavailable | PrepareError::Rpc(_) => admin_client_roles::chain_error(crate::chain_settings::SnapshotError::Unavailable),
    }
}

pub(super) fn missing(id: Uuid) -> Response {
    crate::login_http::problem(StatusCode::NOT_FOUND, &format!("policy {id}"))
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    target: Option<Uuid>,
    policy: &Value,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let (id, status, action) = if let Some(id) = target {
        if !replace_metadata(&mut tx, id, policy).await? {
            return Ok(missing(id));
        }
        (id, StatusCode::OK, "iam.policy.update")
    } else {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO iam_policies (id,name,description) VALUES ($1,$2,$3)")
            .bind(id)
            .bind(policy["name"].as_str())
            .bind(policy["description"].as_str())
            .execute(&mut *tx)
            .await?;
        (id, StatusCode::CREATED, "iam.policy.create")
    };
    sqlx::query("INSERT INTO iam_policy_statements (id,policy_id,sort_order,sid,effect,actions,resources,conditions)
                 SELECT gen_random_uuid(),$1,ordinality-1,item->>'sid',item->>'effect',item->'actions',item->'resources',item->'conditions'
                 FROM jsonb_array_elements($2) WITH ORDINALITY AS entries(item,ordinality)")
        .bind(id).bind(&policy["statements"]).execute(&mut *tx).await?;
    let stored = statements::policies(&mut tx, Some(id))
        .await?
        .pop()
        .ok_or(sqlx::Error::RowNotFound)?;
    crate::admin_audit::append(
        &mut tx,
        action,
        Some(actor),
        ("iam_policy", &id.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((status, Json(stored)).into_response())
}

async fn replace_metadata(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    policy: &Value,
) -> Result<bool, sqlx::Error> {
    let locked =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_policies WHERE id=$1 FOR NO KEY UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
    if locked.is_none() {
        return Ok(false);
    }
    // Historical statements must be readable before a replacement can proceed.
    statements::validate_stored_policy(tx, id).await?;
    sqlx::query("UPDATE iam_policies SET name=COALESCE($2,name), description=COALESCE($3,description),version=version+1,updated_at=now() WHERE id=$1")
        .bind(id).bind(policy["name"].as_str()).bind(policy["description"].as_str()).execute(&mut **tx).await?;
    sqlx::query("DELETE FROM iam_policy_statements WHERE policy_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(true)
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn replacing_a_historical_policy_accepts_stored_non_string_values() -> sqlx::Result<()> {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE iam_policies (id uuid, name text, description text, version int default 1,
                 is_active bool default true, chain_policy_id int, created_at timestamptz default now(),
                 updated_at timestamptz) ON COMMIT DROP;
             CREATE TEMP TABLE iam_policy_statements (id uuid, policy_id uuid, sid text, effect text,
                 actions jsonb, resources jsonb default '[]', conditions jsonb, sort_order int) ON COMMIT DROP;",
        )
        .execute(&mut *tx)
        .await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO iam_policies(id,name) VALUES($1,'historical')")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            r#"INSERT INTO iam_policy_statements(id,policy_id,effect,actions,conditions)
               VALUES(gen_random_uuid(),$1,'allow','[123,{"old":true}]',
                      '[{"operator":"StringEquals","key":7,"value":null}]')"#,
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        assert!(replace_metadata(&mut tx, id, &json!({"description":"repaired"})).await?);
        let state: (i32,i64) = sqlx::query_as(
            "SELECT version,(SELECT count(*) FROM iam_policy_statements) FROM iam_policies WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(state, (2, 0));
        tx.rollback().await
    }

    #[test]
    fn missing_chain_targets_follow_the_selected_group_policy_operation() {
        let group = Uuid::new_v4();
        let policy = Uuid::new_v4();
        for (attach, expected) in [
            (true, StatusCode::NOT_FOUND),
            (false, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let mutation = IamMutation::GroupPolicy {
                group,
                policy,
                attach,
            };
            for error in [
                PrepareError::MissingGroup(group),
                PrepareError::MissingPolicy(policy),
            ] {
                assert_eq!(preparation_error(&mutation, error).status(), expected);
            }
        }
    }
}
