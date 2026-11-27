//! Withdraw one operator-managed role assignment.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem};
use axum::extract::RawQuery;

pub(in crate::profile) async fn revoke(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((user, client, key)): Path<(String, String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    if method != Method::DELETE {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return response;
    }
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let Ok(chain) = authority(&state).await else {
        return internal();
    };
    let user = crate::query::path_uuid(&user, "user_id");
    let org = url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == "organization_id")
        .last()
        .map(|(_, value)| crate::query::uuid_field(&value, "query", "organization_id"))
        .transpose();
    let assignment = match (user, org) {
        (Ok(user), Ok(org)) => Assignment {
            user,
            client,
            key,
            org,
        },
        (user, org) => {
            return passkeys::validation(user.err().into_iter().chain(org.err()).collect());
        }
    };
    match assignment.check_target(&mut tx).await {
        Ok(None) => (),
        Ok(Some(error)) => return error,
        Err(_) => return internal(),
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    assignment
        .revoke(tx, &state, chain, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

impl Assignment {
    async fn revoke(
        &self,
        mut tx: Transaction<'_, Postgres>,
        state: &Profile,
        chain: Option<crate::chain_settings::Chain>,
        actor: (Uuid, Option<&str>),
        origin: SessionOrigin<'_>,
    ) -> Result<Response, sqlx::Error> {
        let global = format!("rp:{}:{}", self.client, self.key);
        let scoped = self.org.map(|org| format!("{global}@{org}"));
        let selected = scoped.as_deref().unwrap_or(&global);
        if let Some(chain) = chain {
            tx.commit().await?;
            let groups = match chain.group_catalog().await {
                Ok(groups) => groups,
                Err(error) => return Ok(chain_error(error)),
            };
            tx = state.pool.begin().await?;
            if let Some(error) = self.chain_outcome(&mut tx, &groups, selected).await? {
                return Ok(error);
            }
        } else {
            let Some(global_id) = group_id(&mut tx, &global).await? else {
                return Ok(missing_role(&self.client, &self.key));
            };
            if global_key(&self.client, &global).is_none() {
                return Ok(missing_role(&self.client, &self.key));
            }
            let group = match scoped {
                Some(name) => group_id(&mut tx, &name).await?,
                None => Some(global_id),
            };
            if let Some(group) = group
                && let Some(error) = self.withdraw(&mut tx, state, group).await?
            {
                return Ok(error);
            }
        }
        crate::admin_audit::append(
            &mut tx,
            "client_role.revoke",
            Some(actor),
            ("user", &self.user.to_string()),
            self.metadata(),
            origin,
        )
        .await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    async fn chain_outcome(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        groups: &[(String, Option<String>, i64)],
        selected: &str,
    ) -> Result<Option<Response>, sqlx::Error> {
        if !groups
            .iter()
            .any(|g| global_key(&self.client, &g.0).as_deref() == Some(&self.key))
        {
            return Ok(Some(missing_role(&self.client, &self.key)));
        }
        if !groups.iter().any(|g| g.0 == selected) {
            return Ok(None);
        }
        let linked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM iam_identities WHERE user_id=$1 AND chain_token_id IS NOT NULL)",
        )
        .bind(self.user)
        .fetch_one(&mut **tx)
        .await?;
        let error = if linked {
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Blockchain role revocation unavailable",
            )
        } else {
            no_identity()
        };
        Ok(Some(error))
    }

    async fn withdraw(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        state: &Profile,
        group: Uuid,
    ) -> Result<Option<Response>, sqlx::Error> {
        let identity: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM iam_identities WHERE user_id=$1")
                .bind(self.user)
                .fetch_optional(&mut **tx)
                .await?;
        let Some(identity) = identity else {
            return Ok(Some(no_identity()));
        };
        if state.registration.hooks && registration::pending_hook(tx, "role_revoked").await? {
            return Ok(Some(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Role revocation hook dispatcher unavailable",
            )));
        }
        sqlx::query("DELETE FROM iam_group_members WHERE group_id=$1 AND identity_id=$2")
            .bind(group)
            .bind(identity)
            .execute(&mut **tx)
            .await?;
        if state.registration.webhooks {
            let mut data = self.metadata();
            data["user_id"] = json!(self.user);
            registration::enqueue_event(tx, "role.revoked", data, Utc::now()).await?;
        }
        Ok(None)
    }
}

fn no_identity() -> Response {
    problem(
        StatusCode::CONFLICT,
        "user has no IAM identity; nothing to revoke",
    )
}

async fn group_id(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM iam_groups WHERE name=$1 ORDER BY created_at,id LIMIT 1 FOR KEY SHARE",
    )
    .bind(name)
    .fetch_optional(&mut **tx)
    .await
}
