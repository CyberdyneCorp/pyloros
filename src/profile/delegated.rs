//! Service-client authorization for delegated role management.
use super::*;

pub(super) async fn client(state: &Profile, headers: &HeaderMap) -> Result<String, Box<Response>> {
    use crate::{csrf::bearer, login_http::service_identity, token_revocation::VerifiedToken};
    let required = || service_identity::unauthorized("Service token required");
    let claims = bearer(headers)
        .and_then(|raw| state.verify.as_ref()?.service_claims(raw))
        .ok_or_else(required)?;
    let Ok(VerifiedToken::Service { client, id, .. }) =
        VerifiedToken::from_verified_claims(&claims)
    else {
        return Err(required());
    };
    service_identity::registration(&state.pool, &client, id, state.enforce)
        .await
        .map_err(|_| Box::new(internal()))?
        .map_err(service_identity::unauthorized)?;
    if !claims["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .any(|scope| scope == "roles:manage")
    {
        return Err(Box::new(crate::login_http::problem(
            StatusCode::FORBIDDEN,
            "Insufficient scope: roles:manage required",
        )));
    }
    Ok(client)
}

pub(super) enum RoleCaller {
    Operator(Uuid, Option<String>),
    Client(String),
}

impl RoleCaller {
    pub(super) async fn authorize(
        state: &Profile,
        headers: &HeaderMap,
        delegated: bool,
    ) -> Result<(Transaction<'static, Postgres>, Self), Box<Response>> {
        if delegated {
            let client = client(state, headers).await?;
            let tx = state.pool.begin().await.map_err(|_| Box::new(internal()))?;
            Ok((tx, Self::Client(client)))
        } else {
            let (tx, id, email) = administrator::operator(state, headers).await?;
            Ok((tx, Self::Operator(id, email)))
        }
    }

    pub(super) fn client_id(&self) -> Option<&str> {
        match self {
            Self::Client(id) => Some(id),
            Self::Operator(..) => None,
        }
    }

    pub(super) fn actor(&self) -> crate::admin_audit::Actor<'_> {
        match self {
            Self::Operator(id, email) => {
                crate::admin_audit::Actor::User(Some((*id, email.as_deref())))
            }
            Self::Client(client) => crate::admin_audit::Actor::Client(client),
        }
    }
}

pub(super) struct CatalogCaller {
    pub(super) client: String,
    principal: RoleCaller,
}

impl CatalogCaller {
    pub(super) fn actor(&self) -> crate::admin_audit::Actor<'_> {
        self.principal.actor()
    }

    pub(super) async fn authorize(
        state: &Profile,
        headers: &HeaderMap,
        requested_client: Option<String>,
    ) -> Result<(Transaction<'static, Postgres>, Self), Box<Response>> {
        let (tx, principal) =
            RoleCaller::authorize(state, headers, requested_client.is_none()).await?;
        let client = requested_client
            .or_else(|| principal.client_id().map(str::to_owned))
            .expect("catalog caller has a client");
        Ok((tx, Self { client, principal }))
    }
}
