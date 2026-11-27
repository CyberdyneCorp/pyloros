//! Operator reads used by the user administration panel.
use super::*;
use crate::{
    chain_settings::{Chain, ChainSettings},
    login_http::problem,
};
use axum::extract::Path;

mod assignments;
mod token;

enum View {
    Token,
    Assignments,
}

impl View {
    async fn authority(&self, settings: &ChainSettings) -> Result<Option<Chain>, sqlx::Error> {
        let chain = match self {
            Self::Token => settings.provider().await,
            Self::Assignments => settings.membership_source().await,
        };
        if let Some(provider) = &chain {
            provider.validate_signer()?;
        }
        Ok(chain)
    }
}

pub(in crate::profile) async fn user_token(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    read(&state, method, &headers, &raw, View::Token).await
}
pub(in crate::profile) async fn user_iam(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    read(&state, method, &headers, &raw, View::Assignments).await
}
async fn read(
    state: &Profile,
    method: Method,
    headers: &HeaderMap,
    path: &str,
    view: View,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(state, headers).await {
        Ok(ctx) => ctx,
        Err(response) => return *response,
    };
    let Ok(chain) = view.authority(&state.blockchain).await else {
        return internal();
    };
    let id = match crate::query::path_uuid(path, "user_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    if let (View::Assignments, Some(chain)) = (&view, &chain) {
        return assignments::remote(tx, chain, id)
            .await
            .unwrap_or_else(|_| internal());
    }
    let metadata =
        sqlx::query_scalar::<_, String>("SELECT extra_metadata::text FROM users WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await;
    let metadata = match metadata {
        Ok(Some(metadata)) => metadata,
        Ok(None) => {
            return problem(
                StatusCode::NOT_FOUND,
                &match view {
                    View::Token => "User not found".into(),
                    View::Assignments => id.to_string(),
                },
            );
        }
        Err(_) => return internal(),
    };
    let Ok(normalized) = admin_organizations::normalized_storage(&metadata) else {
        return internal();
    };
    match view {
        View::Token => {
            if tx.commit().await.is_err() {
                return internal();
            }
            token::response(normalized.as_deref().unwrap_or(&metadata), chain.as_ref()).await
        }
        View::Assignments => assignments::postgres(&mut tx, id)
            .await
            .map(|doc| Json(doc).into_response())
            .unwrap_or_else(|_| internal()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_settings::Update;

    #[tokio::test]
    async fn token_reads_use_deployment_and_prefer_runtime_configuration() {
        let settings = ChainSettings::default();
        let configuration = |identity: &str| Update {
            enabled: Some(true),
            rpc_url: Some("http://localhost".into()),
            identity_contract_address: Some(identity.into()),
            private_key: Some(zeroize::Zeroizing::new(format!("{:064x}", 1))),
            ..Update::default()
        };
        settings.update(configuration("deployment")).await;
        let deployed = ChainSettings::with_deployment(settings.provider().await.unwrap());
        assert!(
            View::Assignments
                .authority(&deployed)
                .await
                .unwrap()
                .is_none()
        );
        assert!(View::Token.authority(&deployed).await.unwrap().is_some());
        deployed.update(configuration("runtime")).await;
        deployed
            .update(Update {
                private_key: Some(zeroize::Zeroizing::new("invalid".into())),
                ..Update::default()
            })
            .await;
        assert!(View::Token.authority(&deployed).await.is_err());
    }
}
