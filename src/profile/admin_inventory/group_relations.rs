//! Dispatch authorized group policy and membership edits to the selected provider.
use super::*;
use crate::{chain_settings::IamMutation, grant_response::SessionOrigin, request_json::fields};
use axum::extract::Path;
use serde_json::value::RawValue;

enum Parent {
    User(String),
    Group(String),
}
enum Child {
    Body(Option<Box<RawValue>>),
    Path(String),
}
impl Parent {
    fn ids(&self, child: &Child) -> Result<(Uuid, Uuid), Box<Response>> {
        let (raw, name, field) = match self {
            Self::User(raw) => (raw, "user_id", "group_id"),
            Self::Group(raw) => (raw, "group_id", "policy_id"),
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
                Parent::Group(parent),
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
                Parent::User(parent),
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
        Parent::Group(parent),
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
        Parent::User(parent),
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
    parent: Parent,
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
            Parent::User(_) => {
                return group_members::prepare_chain(&chain, tx, owner, target, add).await;
            }
            Parent::Group(_) => IamMutation::GroupPolicy {
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
        Parent::User(_) => group_members::store(tx, owner, target, add, actor, origin).await,
        Parent::Group(_) => group_policies::store(tx, owner, target, add, actor, origin).await,
    }
    .unwrap_or_else(|_| internal())
}
