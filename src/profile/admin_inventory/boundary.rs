//! Operator identity lookup and audited changes to a single permission boundary.
use super::*;
use crate::{
    chain_settings::IamMutation, grant_response::SessionOrigin, login_http::problem,
    request_json::fields,
};
use axum::extract::Path;
use serde_json::value::RawValue;

pub(in crate::profile) async fn lookup(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(record) => record,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let id = match crate::query::path_uuid(&raw, "identity_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        if let Err(error) = chain.check_user_catalog().await {
            return admin_client_roles::chain_error(error);
        }
        // The Web3 catalog currently has no enumerable identities.
    } else {
        match user_identity::details(&mut tx, user_identity::Lookup::Identity(id)).await {
            Ok(Some((_, record))) => return Json(record).into_response(),
            Ok(None) => {}
            Err(_) => return internal(),
        }
    }
    problem(StatusCode::NOT_FOUND, "Identity not found")
}

pub(in crate::profile) async fn set(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    match fields::document(&headers, &bytes) {
        Ok(doc) => change(&state, peer, &headers, &raw, Operation::Set(doc)).await,
        Err(error) => *error,
    }
}
pub(in crate::profile) async fn clear(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    change(&state, peer, &headers, &raw, Operation::Clear).await
}
enum Operation {
    Set(Option<Box<RawValue>>),
    Clear,
}

impl Operation {
    fn targets(self, raw: &str) -> Result<(Uuid, Option<Uuid>), Box<Response>> {
        let id = crate::query::path_uuid(raw, "identity_id");
        match self {
            Self::Set(Some(doc)) => {
                input::relation_ids(&doc, id, "policy_id").map(|(id, policy)| (id, Some(policy)))
            }
            Self::Set(None) => Err(Box::new(internal())),
            Self::Clear => id
                .map(|id| (id, None))
                .map_err(|issue| Box::new(passkeys::validation(vec![issue]))),
        }
    }
}
async fn change(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    raw: &str,
    operation: Operation,
) -> Response {
    let (tx, actor, email) = match administrator::operator(state, headers).await {
        Ok(record) => record,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(state).await else {
        return internal();
    };
    let (identity, policy) = match operation.targets(raw) {
        Ok(targets) => targets,
        Err(error) => return *error,
    };
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        return writes::prepare_chain_write(&chain, IamMutation::Boundary { identity, policy })
            .await;
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    store(tx, identity, policy, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}
async fn store(
    mut tx: Transaction<'_, Postgres>,
    identity: Uuid,
    policy: Option<Uuid>,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    // A concurrent boundary insert holds a foreign-key lock on the identity.
    // Wait for it before clearing, even if there was no committed boundary yet.
    let record = sqlx::query_as::<_, (String, String)>(
        "SELECT status,transfer_mode FROM iam_identities WHERE id=$1 FOR UPDATE",
    )
    .bind(identity)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(policy) = policy else {
        sqlx::query("DELETE FROM iam_permission_boundaries WHERE identity_id=$1")
            .bind(identity)
            .execute(&mut *tx)
            .await?;
        return removal::commit_deletion(
            tx,
            actor,
            "iam.identity.boundary.clear",
            ("iam_identity", identity),
            origin,
        )
        .await;
    };
    let Some((status, mode)) = record else {
        return Ok(problem(
            StatusCode::NOT_FOUND,
            &format!("identity {identity}"),
        ));
    };
    user_identity::validate_identity(&status, &mode)?;
    if !group_policies::lock_policy(&mut tx, policy).await? {
        return Ok(writes::missing(policy));
    }
    sqlx::query(
        "INSERT INTO iam_permission_boundaries(identity_id,policy_id) VALUES($1,$2)
       ON CONFLICT(identity_id) DO UPDATE SET policy_id=EXCLUDED.policy_id",
    )
    .bind(identity)
    .bind(policy)
    .execute(&mut *tx)
    .await?;
    crate::admin_audit::append(
        &mut tx,
        "iam.identity.boundary.set",
        Some(actor),
        ("iam_identity", &identity.to_string()),
        json!({"policy_id":policy}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn clear_waits_for_a_boundary_inserted_by_another_writer() -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await?;
        let schema = format!("boundary_{}", Uuid::new_v4().simple());
        let mut setup = pool.begin().await?;
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema};
            CREATE TABLE iam_identities(id uuid primary key,status text,transfer_mode text);
            CREATE TABLE iam_permission_boundaries(identity_id uuid primary key REFERENCES iam_identities(id),policy_id uuid);"))
            .execute(&mut *setup).await?;
        let identity = Uuid::new_v4();
        sqlx::query("INSERT INTO iam_identities VALUES($1,'active','soulbound')")
            .bind(identity)
            .execute(&mut *setup)
            .await?;
        setup.commit().await?;
        let mut writer = pool.begin().await?;
        let path = format!("SET LOCAL search_path TO {schema}");
        sqlx::query(&path).execute(&mut *writer).await?;
        sqlx::query("INSERT INTO iam_permission_boundaries VALUES($1,$2)")
            .bind(identity)
            .bind(Uuid::new_v4())
            .execute(&mut *writer)
            .await?;
        let mut clearer = pool.begin().await?;
        sqlx::query(&path).execute(&mut *clearer).await?;
        sqlx::query("SET LOCAL lock_timeout='150ms'")
            .execute(&mut *clearer)
            .await?;
        let outcome = store(
            clearer,
            identity,
            None,
            (Uuid::new_v4(), None),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await;
        writer.rollback().await?;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await?;
        assert_eq!(
            outcome
                .unwrap_err()
                .as_database_error()
                .and_then(|e| e.code())
                .as_deref(),
            Some("55P03")
        );
        Ok(())
    }
}
