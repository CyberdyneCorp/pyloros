//! Create a global role in the active IAM provider.
use super::*;
use crate::{
    browser_prompt::quoted_string, grant_response::SessionOrigin, login_http::problem,
    request_json::fields,
};

struct NewRole {
    key: String,
    description: Option<String>,
}

fn input(value: Value) -> Result<NewRole, Vec<Value>> {
    let mut fields = admin_fields::Fields {
        body: admin_fields::object(&value)?,
        issues: vec![],
    };
    let key = fields.string("role_key", Some(48), true);
    let description = fields.string("description", Some(1024), false);
    if !fields.issues.is_empty() {
        return Err(fields.issues);
    }
    Ok(NewRole {
        key: key.expect("validated role key"),
        description,
    })
}

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(client): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match fields::document(&headers, &bytes) {
        Ok(body) => body,
        Err(error) => return *error,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Ok(chain) = authority(&state).await else {
        return internal();
    };
    let Some(body) = body else { return internal() };
    let role = match fields::validate_document(&body, &["role_key", "description"], input) {
        Ok(role) => role,
        Err(error) => return *error,
    };
    if !crate::token_authorization::valid_role_key(&role.key) {
        return problem(
            StatusCode::BAD_REQUEST,
            &format!(
                "invalid role_key {}: must match [a-z0-9][a-z0-9_-]{{0,47}}",
                quoted_string(&role.key)
            ),
        );
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    insert(tx, chain, &client, role, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

fn conflict(client: &str, key: &str, names: impl Iterator<Item = String>) -> Option<Response> {
    let mut count = 0;
    for existing in names.filter_map(|name| global_key(client, &name)) {
        if existing == key {
            return Some(problem(
                StatusCode::CONFLICT,
                &format!(
                    "role {} already exists for client {}",
                    quoted_string(key),
                    quoted_string(client)
                ),
            ));
        }
        count += 1;
    }
    (count >= 64).then(|| {
        problem(
            StatusCode::CONFLICT,
            &format!(
                "catalog full: client {} already has 64 roles",
                quoted_string(client)
            ),
        )
    })
}

async fn insert(
    mut tx: Transaction<'_, Postgres>,
    chain: Option<crate::chain_settings::Chain>,
    client: &str,
    role: NewRole,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    if !active_client_for_update(&mut tx, client).await? {
        return Ok(admin_permissions::unknown_client(client));
    }
    if let Some(chain) = chain {
        tx.commit().await?;
        let groups = match chain.group_catalog().await {
            Ok(groups) => groups,
            Err(error) => return Ok(chain_error(error)),
        };
        return Ok(
            conflict(client, &role.key, groups.into_iter().map(|g| g.0)).unwrap_or_else(|| {
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Blockchain role creation unavailable",
                )
            }),
        );
    }
    let prefix = format!("rp:{client}:");
    let names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM iam_groups WHERE starts_with(name,$1)")
            .bind(&prefix)
            .fetch_all(&mut *tx)
            .await?;
    if let Some(response) = conflict(client, &role.key, names.into_iter()) {
        return Ok(response);
    }
    let name = format!("{prefix}{}", role.key);
    if global_key(client, &name).is_none() {
        return Ok(internal());
    }
    sqlx::query("INSERT INTO iam_groups(id,name,description) VALUES($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(name)
        .bind(&role.description)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM client_role_permissions WHERE client_id=$1 AND role_key=$2")
        .bind(client)
        .bind(&role.key)
        .execute(&mut *tx)
        .await?;
    crate::admin_audit::append(
        &mut tx,
        "client_role.create",
        Some(actor),
        ("client_role", &format!("{client}:{}", role.key)),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(Role {
            client_id: client,
            role_key: role.key,
            description: role.description,
            member_count: 0,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn failed_audit_preserves_the_previous_mapping_and_allows_retry() {
        use sqlx::Acquire;

        let db = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = db.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE oauth_clients(client_id text, active boolean);
             CREATE TEMP TABLE iam_groups(id uuid, name text, description text);
             CREATE TEMP TABLE client_role_permissions(client_id text, role_key text);
             CREATE TEMP TABLE audit_chain_head(id int primary key, head_hash text);
             CREATE TEMP TABLE admin_action_logs(id uuid, action text, target_type text,
                target_id text, extra_metadata jsonb, ip_address inet, user_agent text,
                created_at timestamptz, prev_hash text, row_hash text, actor_user_id uuid,
                actor_type text,actor_client_id text,actor_email text, CONSTRAINT refuse_audit CHECK (false));
             INSERT INTO oauth_clients VALUES ('app', true);
             INSERT INTO client_role_permissions VALUES ('app','editor'),('other','editor');",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let role = || NewRole {
            key: "editor".into(),
            description: None,
        };
        let actor = (Uuid::new_v4(), None);
        let origin = SessionOrigin {
            ip: None,
            user_agent: None,
        };
        assert!(
            insert(
                tx.begin().await.unwrap(),
                None,
                "app",
                role(),
                actor,
                origin
            )
            .await
            .is_err()
        );
        let state = "SELECT (SELECT count(*) FROM iam_groups), (SELECT count(*) FROM client_role_permissions WHERE client_id='app'), (SELECT count(*) FROM client_role_permissions WHERE client_id='other'), (SELECT count(*) FROM admin_action_logs)";
        let snapshot = || sqlx::query_as::<_, (i64, i64, i64, i64)>(state);
        assert_eq!(snapshot().fetch_one(&mut *tx).await.unwrap(), (0, 1, 1, 0));
        sqlx::query("ALTER TABLE admin_action_logs DROP CONSTRAINT refuse_audit")
            .execute(&mut *tx)
            .await
            .unwrap();
        let result = insert(
            tx.begin().await.unwrap(),
            None,
            "app",
            role(),
            actor,
            origin,
        )
        .await
        .unwrap();
        assert_eq!(result.status(), StatusCode::CREATED);
        assert_eq!(snapshot().fetch_one(&mut *tx).await.unwrap(), (1, 0, 1, 1));
    }

    #[test]
    fn capacity_counts_only_global_roles_owned_by_the_client() {
        let mut names: Vec<_> = (0..63).map(|i| format!("rp:app:r{i}")).collect();
        names.extend(
            [
                "rp:app:r0@df6905fa-bb14-4a77-a2d9-dfa9bc899748",
                "rp:app:nested:r1",
                "rp:app:invalid space",
            ]
            .map(str::to_owned),
        );
        assert!(conflict("app", "last", names.clone().into_iter()).is_none());
        names.push("rp:app:last".into());
        assert_eq!(
            conflict("app", "extra", names.into_iter())
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
    }
}
