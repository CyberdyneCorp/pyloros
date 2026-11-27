//! Dispatch authorized group and user IAM relationship edits to the selected provider.
use super::*;
use crate::{chain_settings::IamMutation, grant_response::SessionOrigin, request_json::fields};
use axum::extract::Path;
use serde_json::value::RawValue;

enum Relation {
    Membership(String),
    UserPolicy(String),
    GroupPolicy(String),
}
enum Child {
    Body(Option<Box<RawValue>>),
    Path(String),
}
impl Relation {
    fn ids(&self, child: &Child) -> Result<(Uuid, Uuid), Box<Response>> {
        let (raw, name, field) = match self {
            Self::UserPolicy(raw) => (raw, "user_id", "policy_id"),
            Self::Membership(raw) => (raw, "user_id", "group_id"),
            Self::GroupPolicy(raw) => (raw, "group_id", "policy_id"),
        };
        let parent = crate::query::path_uuid(raw, name);
        match child {
            Child::Body(Some(raw)) => input::relation_ids(raw, parent, field),
            Child::Body(None) => Err(Box::new(internal())),
            Child::Path(raw) => match (parent, crate::query::path_uuid(raw, field)) {
                (Ok(parent), Ok(child)) => Ok((parent, child)),
                (parent, child) => Err(Box::new(passkeys::validation(
                    parent.err().into_iter().chain(child.err()).collect(),
                ))),
            },
        }
    }
}

pub(in crate::profile) async fn attach_group_policy(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(parent): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    match fields::document(&headers, &bytes) {
        Ok(raw) => {
            change(
                &state,
                peer,
                &headers,
                Relation::GroupPolicy(parent),
                Child::Body(raw),
            )
            .await
        }
        Err(error) => *error,
    }
}

pub(in crate::profile) async fn add_member(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(parent): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    match fields::document(&headers, &bytes) {
        Ok(raw) => {
            change(
                &state,
                peer,
                &headers,
                Relation::Membership(parent),
                Child::Body(raw),
            )
            .await
        }
        Err(error) => *error,
    }
}

pub(in crate::profile) async fn detach_group_policy(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((parent, child)): Path<(String, String)>,
) -> Response {
    change(
        &state,
        peer,
        &headers,
        Relation::GroupPolicy(parent),
        Child::Path(child),
    )
    .await
}

pub(in crate::profile) async fn remove_member(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((parent, child)): Path<(String, String)>,
) -> Response {
    change(
        &state,
        peer,
        &headers,
        Relation::Membership(parent),
        Child::Path(child),
    )
    .await
}

pub(in crate::profile) async fn attach_user_policy(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(parent): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    match fields::document(&headers, &bytes) {
        Ok(raw) => {
            change(
                &state,
                peer,
                &headers,
                Relation::UserPolicy(parent),
                Child::Body(raw),
            )
            .await
        }
        Err(error) => *error,
    }
}

pub(in crate::profile) async fn detach_user_policy(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((parent, child)): Path<(String, String)>,
) -> Response {
    change(
        &state,
        peer,
        &headers,
        Relation::UserPolicy(parent),
        Child::Path(child),
    )
    .await
}

pub(in crate::profile) async fn delete_only() -> Response {
    let mut response =
        crate::login_http::problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    response
        .headers_mut()
        .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
    response
}

async fn change(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    parent: Relation,
    child: Child,
) -> Response {
    let (tx, actor, email) = match administrator::operator(state, headers).await {
        Ok(record) => record,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(state).await else {
        return internal();
    };
    let (owner, target) = match parent.ids(&child) {
        Ok(ids) => ids,
        Err(error) => return *error,
    };
    let add = matches!(child, Child::Body(_));
    if let Some(chain) = chain {
        let mutation = match parent {
            Relation::UserPolicy(_) => {
                return user_policies::prepare_chain(&chain, tx, owner, target, add).await;
            }
            Relation::Membership(_) => {
                return group_members::prepare_chain(&chain, tx, owner, target, add).await;
            }
            Relation::GroupPolicy(_) => IamMutation::GroupPolicy {
                group: owner,
                policy: target,
                attach: add,
            },
        };
        if tx.commit().await.is_err() {
            return internal();
        }
        return writes::prepare_chain_write(&chain, mutation).await;
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    let actor = (actor, email.as_deref());
    match parent {
        Relation::UserPolicy(_) => {
            user_policies::store(tx, owner, target, add, actor, origin).await
        }
        Relation::Membership(_) => {
            group_members::store(tx, owner, target, add, actor, origin).await
        }
        Relation::GroupPolicy(_) => {
            group_policies::store(tx, owner, target, add, actor, origin).await
        }
    }
    .unwrap_or_else(|_| internal())
}
