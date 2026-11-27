//! Remove an IAM role, its role sessions and its policy attachments.
use super::*;
use crate::grant_response::SessionOrigin;
use axum::extract::Path;

pub(in crate::profile) async fn delete_role(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let role = match crate::query::path_uuid(&raw, "role_id") {
        Ok(role) => role,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        return match chain.operator_roles().await {
            Ok(_) => assume_role::missing(role),
            Err(error) => admin_client_roles::chain_error(error),
        };
    }
    // Two operators can both observe the role before either deletion commits.
    match sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT FROM iam_roles WHERE id=$1)")
        .bind(role)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(true) => {}
        Ok(false) => return assume_role::missing(role),
        Err(_) => return internal(),
    }
    if sqlx::query("DELETE FROM iam_roles WHERE id=$1")
        .bind(role)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return internal();
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    removal::commit_deletion(
        tx,
        (actor, email.as_deref()),
        "iam.role.delete",
        ("iam_role", role),
        origin,
    )
    .await
    .unwrap_or_else(|_| internal())
}
