//! Remove organization membership and the role assignments that depend on it.
use super::*;
use crate::{chain_settings::Chain, grant_response::SessionOrigin, login_http::problem};

pub(in crate::profile) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((user, org)): Path<(String, String)>,
) -> Response {
    if method != Method::DELETE {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return response;
    }
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(e) => return *e,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let ids = (
        crate::query::path_uuid(&user, "user_id"),
        crate::query::path_uuid(&org, "organization_id"),
    );
    let (user, org) = match ids {
        (Ok(user), Ok(org)) => (user, org),
        (user, org) => {
            return passkeys::validation(user.err().into_iter().chain(org.err()).collect());
        }
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    apply(
        tx,
        &state,
        chain,
        user,
        org,
        (actor, email.as_deref()),
        origin,
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn apply(
    mut tx: Transaction<'_, Postgres>,
    state: &Profile,
    chain: Option<Chain>,
    user: Uuid,
    org: Uuid,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let record: Option<(Option<Uuid>, String)> =
        sqlx::query_as("SELECT organization_id,extra_metadata::text FROM users WHERE id=$1")
            .bind(user)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((primary, metadata)) = record else {
        return Ok(problem(StatusCode::NOT_FOUND, &format!("user {user}")));
    };
    let normalized = metadata::normalized_storage(&metadata)?;
    let org_metadata: Option<String> =
        sqlx::query_scalar("SELECT extra_metadata::text FROM organizations WHERE id=$1")
            .bind(org)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(org_metadata) = org_metadata else {
        return Ok(problem(StatusCode::NOT_FOUND, &org.to_string()));
    };
    metadata::normalized_storage(&org_metadata)?;
    sqlx::query("DELETE FROM user_organizations WHERE user_id=$1 AND organization_id=$2")
        .bind(user)
        .bind(org)
        .execute(&mut *tx)
        .await?;
    if primary == Some(org) {
        clear_primary(&mut tx, user, normalized.as_deref().unwrap_or(&metadata)).await?;
    }
    let revoked = match revoke_roles(&mut tx, state, chain, user, org).await? {
        Ok(revoked) => revoked,
        Err(response) => return Ok(*response),
    };
    crate::admin_audit::append(
        &mut tx,
        "user.remove_organization",
        Some(actor),
        ("user", &user.to_string()),
        json!({"organization_id":org,"revoked_roles":revoked}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::NO_CONTENT,
        [(header::CONTENT_TYPE, "application/json")],
    )
        .into_response())
}

async fn clear_primary(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    metadata: &str,
) -> Result<(), sqlx::Error> {
    // A concurrent removal can finish while the membership DELETE is waiting.
    let (has_primary, metadata_changed): (bool,bool) = sqlx::query_as(
        "SELECT organization_id IS NOT NULL, extra_metadata <> $2::text::jsonb FROM users WHERE id=$1",
    ).bind(user).bind(metadata).fetch_one(&mut **tx).await?;
    let update = match (has_primary, metadata_changed) {
        (true, true) => {
            "UPDATE users SET organization_id=NULL,extra_metadata=$2::text::jsonb,updated_at=now() WHERE id=$1"
        }
        (false, true) => {
            "UPDATE users SET extra_metadata=$2::text::jsonb,updated_at=now() WHERE id=$1"
        }
        (true, false) => "UPDATE users SET organization_id=NULL,updated_at=now() WHERE id=$1",
        (false, false) => return Ok(()),
    };
    let mut query = sqlx::query(update).bind(user);
    if metadata_changed {
        query = query.bind(metadata);
    }
    query.execute(&mut **tx).await?;
    Ok(())
}

fn scoped(name: &str, org: Uuid) -> Option<(String, String)> {
    let (token, scope) = crate::token_authorization::assignment(name)?;
    if scope != Some(org) {
        return None;
    }
    let (client, key) = token.rsplit_once(':')?;
    Some((client.to_owned(), key.to_owned()))
}

async fn revoke_roles(
    tx: &mut Transaction<'_, Postgres>,
    state: &Profile,
    chain: Option<Chain>,
    user: Uuid,
    org: Uuid,
) -> Result<Result<Vec<String>, Box<Response>>, sqlx::Error> {
    if let Some(chain) = chain {
        let token = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT chain_token_id FROM iam_identities WHERE user_id=$1",
        )
        .bind(user)
        .fetch_optional(&mut **tx)
        .await?
        .flatten();
        return Ok(match chain.membership_names(token).await {
            Err(error) => Err(Box::new(admin_client_roles::chain_error(error))),
            Ok(names) if names.iter().any(|name| scoped(name, org).is_some()) => {
                Err(Box::new(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Blockchain role revocation unavailable",
                )))
            }
            Ok(_) => Ok(Vec::new()),
        });
    }
    let groups = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT g.id,g.name FROM iam_group_members m JOIN iam_groups g ON g.id=m.group_id
         WHERE m.identity_id=(SELECT id FROM iam_identities WHERE user_id=$1)",
    )
    .bind(user)
    .fetch_all(&mut **tx)
    .await?;
    let mut revoked = Vec::new();
    for (group, name) in groups {
        if let Some((client, key)) = scoped(&name, org) {
            revoked.push((client.clone(), key.clone()));
            if let Some(response) =
                admin_client_roles::withdraw_scoped(tx, state, user, org, group, client, key)
                    .await?
            {
                return Ok(Err(Box::new(response)));
            }
        }
    }
    revoked.sort_unstable();
    Ok(Ok(revoked
        .into_iter()
        .map(|(client, key)| format!("{client}:{key}"))
        .collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn retry_after_membership_lock_preserves_an_already_cleared_user_revision()
    -> Result<(), sqlx::Error> {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::query("CREATE TEMP TABLE users(id uuid,organization_id uuid,extra_metadata jsonb,updated_at timestamptz)").execute(&mut *tx).await?;
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES($1,NULL,'{}','2000-01-01Z')")
            .bind(user)
            .execute(&mut *tx)
            .await?;
        clear_primary(&mut tx, user, "{}").await?;
        let preserved: bool =
            sqlx::query_scalar("SELECT updated_at='2000-01-01Z'::timestamptz FROM users")
                .fetch_one(&mut *tx)
                .await?;
        assert!(preserved);
        Ok(())
    }
}
