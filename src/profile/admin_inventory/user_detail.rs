//! Operator reads used by the user administration panel.
use super::*;
use crate::{
    chain_settings::{Chain, ChainSettings, TokenProvider},
    login_http::problem,
};
use axum::extract::Path;

mod assignments;
pub(super) mod token;

enum View {
    Token,
    Assignments,
}

enum Authority {
    Token(TokenProvider),
    Assignments(Option<Chain>),
}

impl View {
    async fn authority(&self, settings: &ChainSettings) -> Result<Authority, sqlx::Error> {
        match self {
            Self::Token => settings.token_provider().await.map(Authority::Token),
            Self::Assignments => {
                let chain = settings.membership_source().await;
                if let Some(provider) = &chain {
                    provider.validate_signer()?;
                }
                Ok(Authority::Assignments(chain))
            }
        }
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
    let Ok(authority) = view.authority(&state.blockchain).await else {
        return internal();
    };
    let id = match crate::query::path_uuid(path, "user_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    if let Authority::Assignments(Some(chain)) = &authority {
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
    match authority {
        Authority::Token(provider) => {
            if tx.commit().await.is_err() {
                return internal();
            }
            token::response(normalized.as_deref().unwrap_or(&metadata), &provider).await
        }
        Authority::Assignments(_) => assignments::postgres(&mut tx, id)
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
        assert!(matches!(
            View::Assignments.authority(&deployed).await.unwrap(),
            Authority::Assignments(None)
        ));
        assert!(matches!(
            View::Token.authority(&deployed).await.unwrap(),
            Authority::Token(TokenProvider::Remote(..))
        ));
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
