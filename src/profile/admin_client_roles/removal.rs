//! Retire a client role and its organization assignments.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem};

pub(in crate::profile) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((client, key)): Path<(String, String)>,
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
        Err(error) => return *error,
    };
    let Ok(chain) = authority(&state).await else {
        return internal();
    };
    if !crate::token_authorization::valid_role_key(&key) {
        return problem(
            StatusCode::BAD_REQUEST,
            &format!(
                "invalid role_key {}: must match [a-z0-9][a-z0-9_-]{{0,47}}",
                crate::browser_prompt::quoted_string(&key)
            ),
        );
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    delete(tx, chain, &client, &key, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

fn matches_role(token: &str, name: &str) -> bool {
    crate::token_authorization::assignment(name).is_some_and(|(role, _)| role == token)
}

async fn delete(
    mut tx: Transaction<'_, Postgres>,
    chain: Option<crate::chain_settings::Chain>,
    client: &str,
    key: &str,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    if !active_client_for_update(&mut tx, client).await? {
        return Ok(admin_permissions::unknown_client(client));
    }
    let token = format!("{client}:{key}");
    if let Some(chain) = chain {
        tx.commit().await?;
        return Ok(match chain.group_catalog().await {
            Err(error) => chain_error(error),
            Ok(groups) if groups.iter().any(|g| matches_role(&token, &g.0)) => problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Blockchain role deletion unavailable",
            ),
            Ok(_) => missing_role(client, key),
        });
    }
    lock_role(&mut tx, client, key).await?;
    let name = format!("rp:{token}");
    let candidates: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id,name FROM iam_groups WHERE name=$1 OR starts_with(name,$2) ORDER BY id FOR UPDATE"
    ).bind(&name).bind(format!("{name}@")).fetch_all(&mut *tx).await?;
    let ids: Vec<_> = candidates
        .into_iter()
        .filter(|(_, name)| matches_role(&token, name))
        .map(|(id, _)| id)
        .collect();
    if ids.is_empty() {
        return Ok(missing_role(client, key));
    }
    sqlx::query("DELETE FROM client_role_permissions WHERE client_id=$1 AND role_key=$2")
        .bind(client)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM iam_groups WHERE id=ANY($1)")
        .bind(ids)
        .execute(&mut *tx)
        .await?;
    crate::admin_audit::append(
        &mut tx,
        "client_role.delete",
        Some(actor),
        ("client_role", &token),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deletion_selects_only_the_named_role_and_its_organization_assignments() {
        let role = "a:reader";
        assert!(matches_role(role, "rp:a:reader"));
        assert!(matches_role(
            role,
            "rp:a:reader@fa071ca4-7772-4868-ba52-f4d52d960b65"
        ));
        assert!(matches_role(
            role,
            "rp:a:reader@fa0-71ca477724868ba52f4d52d960b65"
        ));
        for unrelated in [
            "rp:b:reader",
            "rp:a:readers",
            "rp:a:reader@broken",
            "rp:a:reader@",
        ] {
            assert!(!matches_role(role, unrelated));
        }
    }
}
