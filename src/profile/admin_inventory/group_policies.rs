//! Modify the policies inherited through an IAM group.
use super::*;
use crate::{chain_settings::IamMutation, grant_response::SessionOrigin, request_json::fields};
use axum::extract::Path;
use serde_json::value::RawValue;

enum PolicyId<'a> {
    Attach(Option<Box<RawValue>>),
    Detach(&'a str),
}

pub(in crate::profile) async fn attach_group_policy(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(group): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    match fields::document(&headers, &bytes) {
        Ok(raw) => change(&state, peer, &headers, &group, PolicyId::Attach(raw)).await,
        Err(error) => *error,
    }
}

pub(in crate::profile) async fn detach_group_policy(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((group, policy)): Path<(String, String)>,
) -> Response {
    if method != Method::DELETE {
        let mut response =
            crate::login_http::problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return response;
    }
    change(&state, peer, &headers, &group, PolicyId::Detach(&policy)).await
}

async fn change(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    group: &str,
    reference: PolicyId<'_>,
) -> Response {
    let (tx, actor, email) = match administrator::operator(state, headers).await {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(state).await else {
        return internal();
    };
    let group = crate::query::path_uuid(group, "group_id");
    let attach = matches!(reference, PolicyId::Attach(_));
    let (group, policy) = match reference {
        PolicyId::Attach(Some(raw)) => match input::group_policy(&raw, group) {
            Ok(pair) => pair,
            Err(error) => return *error,
        },
        PolicyId::Attach(None) => return internal(),
        PolicyId::Detach(raw) => match (group, crate::query::path_uuid(raw, "policy_id")) {
            (Ok(g), Ok(p)) => (g, p),
            (g, p) => return passkeys::validation(g.err().into_iter().chain(p.err()).collect()),
        },
    };
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        return writes::prepare_chain_write(
            &chain,
            IamMutation::GroupPolicy {
                group,
                policy,
                attach,
            },
        )
        .await;
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    store(tx, group, policy, attach, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn store(
    mut tx: Transaction<'_, Postgres>,
    group: Uuid,
    policy: Uuid,
    attach: bool,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let action = if attach {
        let locked =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_groups WHERE id=$1 FOR KEY SHARE")
                .bind(group)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            return Ok(delete_group::missing(group));
        }
        let locked_policy =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM iam_policies WHERE id=$1 FOR KEY SHARE")
                .bind(policy)
                .fetch_optional(&mut *tx)
                .await?;
        if locked_policy.is_none() {
            return Ok(writes::missing(policy));
        }
        // Loading the policy also validates its historical statement data.
        statements::policies(&mut tx, Some(policy)).await?;
        sqlx::query(
            "INSERT INTO iam_group_policies(group_id,policy_id) VALUES($1,$2)
             ON CONFLICT (group_id,policy_id) DO NOTHING",
        )
        .bind(group)
        .bind(policy)
        .execute(&mut *tx)
        .await?;
        "iam.group.policy.attach"
    } else {
        sqlx::query("DELETE FROM iam_group_policies WHERE group_id=$1 AND policy_id=$2")
            .bind(group)
            .bind(policy)
            .execute(&mut *tx)
            .await?;
        "iam.group.policy.detach"
    };
    crate::admin_audit::append(
        &mut tx,
        action,
        Some(actor),
        ("iam_group", &group.to_string()),
        json!({"policy_id":policy}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})).into_response())
}
