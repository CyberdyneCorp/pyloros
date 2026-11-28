//! Retire a client role and its organization assignments.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem};

pub(in crate::profile) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(path): Path<RolePath>,
) -> Response {
    if method != Method::DELETE {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return response;
    }
    let (tx, caller) =
        match delegated::CatalogCaller::authorize(&state, &headers, path.client_id).await {
            Ok(result) => result,
            Err(error) => return *error,
        };
    let Ok(chain) = authority(&state).await else {
        return internal();
    };
    let key = path.role_key;
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
    delete(tx, chain, &caller.client, &key, caller.actor(), origin)
        .await
        .unwrap_or_else(|_| internal())
}

fn matches_role(token: &str, name: &str) -> bool {
    crate::token_authorization::assignment(name).is_some_and(|(role, _)| role == token)
}

async fn remove_chain_groups(
    tx: &mut Transaction<'_, Postgres>,
    chain: &crate::chain_settings::Chain,
    client: &str,
    key: &str,
) -> sqlx::Result<Option<Response>> {
    chain.lock_signer(tx).await?;
    let inventory = match chain.snapshot().await {
        Ok(inventory) => inventory,
        Err(error) => return Ok(Some(chain_error(error))),
    };
    let token = format!("{client}:{key}");
    let mut groups: Vec<_> = inventory
        .groups
        .into_iter()
        .filter(|g| matches_role(&token, &g.name))
        .collect();
    if groups.is_empty() {
        return Ok(Some(missing_role(client, key)));
    }
    clear_role_mapping(tx, client, key).await?;
    groups.sort_by_key(|g| !g.name.contains('@'));
    for group in groups {
        if let Err(error) = chain.delete_role_group(group.id).await {
            return Ok(Some(preparation_error(error)));
        }
    }
    Ok(None)
}

async fn delete(
    mut tx: Transaction<'_, Postgres>,
    chain: Option<crate::chain_settings::Chain>,
    client: &str,
    key: &str,
    actor: crate::admin_audit::Actor<'_>,
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    if !active_client_for_update(&mut tx, client).await? {
        return Ok(admin_permissions::unknown_client(client));
    }
    let token = format!("{client}:{key}");
    if let Some(chain) = chain {
        if let Some(response) = remove_chain_groups(&mut tx, &chain, client, key).await? {
            return Ok(response);
        }
    } else {
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
        clear_role_mapping(&mut tx, client, key).await?;
        sqlx::query("DELETE FROM iam_groups WHERE id=ANY($1)")
            .bind(ids)
            .execute(&mut *tx)
            .await?;
    }
    crate::admin_audit::append_sorted_record(
        &mut tx,
        "client_role.delete",
        actor,
        Some(("client_role", Some(&token))),
        &json!({}),
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn delegated_delete_records_the_client_and_returns_an_empty_json_response() {
        use sqlx::Acquire;
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE oauth_clients(client_id text, active boolean);
          CREATE TEMP TABLE iam_groups(id uuid, name text);
          CREATE TEMP TABLE client_role_permissions(client_id text, role_key text);
          CREATE TEMP TABLE audit_chain_head(id int primary key, head_hash text);
          CREATE TEMP TABLE admin_action_logs(id uuid, action text,target_type text,target_id text,
            extra_metadata jsonb,ip_address inet,user_agent text,created_at timestamptz,prev_hash text,
            row_hash text,actor_type text,actor_user_id uuid,actor_email text,actor_client_id text);
          INSERT INTO oauth_clients VALUES ('app',true);
          INSERT INTO iam_groups VALUES(gen_random_uuid(),'rp:app:reader'),(gen_random_uuid(),'rp:sibling:reader');")
            .execute(&mut *tx).await.unwrap();
        let result = delete(
            tx.begin().await.unwrap(),
            None,
            "app",
            "reader",
            crate::admin_audit::Actor::Client("app"),
            SessionOrigin {
                ip: None,
                user_agent: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.status(), StatusCode::NO_CONTENT);
        assert_eq!(result.headers()[header::CONTENT_TYPE], "application/json");
        assert!(
            axum::body::to_bytes(result.into_body(), 128)
                .await
                .unwrap()
                .is_empty()
        );
        let audit: (String, String, String) =
            sqlx::query_as("SELECT actor_type,actor_client_id,target_id FROM admin_action_logs")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(audit, ("client".into(), "app".into(), "app:reader".into()));
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT name FROM iam_groups")
                .fetch_all(&mut *tx)
                .await
                .unwrap(),
            ["rp:sibling:reader"]
        );
    }

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
