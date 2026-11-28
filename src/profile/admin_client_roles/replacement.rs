//! Replace a client role mapping and append its audit entry atomically.
use super::*;
use crate::grant_response::SessionOrigin;
use crate::login_http::problem;
use std::collections::BTreeSet;

pub(super) struct Change<'a> {
    keys: BTreeSet<String>,
    actor: crate::admin_audit::Actor<'a>,
    origin: SessionOrigin<'a>,
}

pub(in crate::profile) async fn put(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<RolePath>,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match crate::request_json::iam_document::document(&headers, &bytes) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let (tx, caller) =
        match delegated::CatalogCaller::authorize(&state, &headers, path.client_id).await {
            Ok(result) => result,
            Err(response) => return *response,
        };
    let Ok(chain) = authority(&state).await else {
        return internal();
    };
    let Some(body) = body else { return internal() };
    let keys = match input(&body) {
        Ok(keys) => keys,
        Err(response) => return *response,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    let change = Change {
        keys,
        actor: caller.actor(),
        origin,
    };
    catalog(
        &state,
        chain,
        tx,
        &caller.client,
        Some(Target {
            key: &path.role_key,
            change: Some(change),
        }),
    )
    .await
    .unwrap_or_else(|_| internal())
}

use crate::request_json::fields::{invalid, validation_input};
use serde_json::value::RawValue;

fn input(raw: &RawValue) -> Result<BTreeSet<String>, Box<Response>> {
    let (model, original) = validation_input(raw, "permissions")?;
    let fields = admin_fields::object_field(&model).map_err(|e| invalid(vec![(e, raw)]))?;
    let location = ["body", "permissions"];
    if !fields.contains_key("permissions") {
        return Err(invalid(vec![(
            json!({"type":"missing","loc":location,"msg":"Field required"}),
            raw,
        )]));
    }
    let Ok(items) = serde_json::from_str::<Vec<&RawValue>>(original.get()) else {
        return Err(invalid(vec![(
            json!({"type":"list_type","loc":location,"msg":"Input should be a valid list"}),
            original,
        )]));
    };
    let n = items.len();
    if n > 256 {
        return Err(invalid(vec![(
            json!({"type":"too_long","loc":location,"msg":format!("List should have at most 256 items after validation, not {n}"),"ctx":{"field_type":"List","max_length":"256","actual_length":n.to_string()}}),
            original,
        )]));
    }
    let mut keys = BTreeSet::new();
    let mut issues = Vec::new();
    for (i, item) in items.into_iter().enumerate() {
        match serde_json::from_str::<String>(item.get()) {
            Ok(key) => { keys.insert(key); }
            Err(_) => issues.push((json!({"type":"string_type","loc":["body","permissions",i],"msg":"Input should be a valid string"}),item)),
        }
    }
    if issues.is_empty() {
        Ok(keys)
    } else {
        Err(invalid(issues))
    }
}

async fn unknown_permissions(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
    submitted: &BTreeSet<String>,
) -> sqlx::Result<Vec<String>> {
    // A JSON string containing NUL cannot match a PostgreSQL text key.
    let candidates: Vec<_> = submitted
        .iter()
        .map(String::as_str)
        .filter(|key| !key.contains('\0'))
        .collect();
    let known: Vec<String> = sqlx::query_scalar(
        "SELECT key FROM client_permissions WHERE client_id=$1 AND key=ANY($2::text[])",
    )
    .bind(client)
    .bind(candidates)
    .fetch_all(&mut **tx)
    .await?;
    Ok(submitted
        .difference(&known.into_iter().collect())
        .map(|key| crate::admin_audit::ascii_json(&json!(key)))
        .collect())
}

impl Change<'_> {
    pub(super) async fn apply(
        self,
        mut tx: Transaction<'_, Postgres>,
        client: &str,
        key: &str,
    ) -> Result<Response, sqlx::Error> {
        let unknown = unknown_permissions(&mut tx, client, &self.keys).await?;
        if !unknown.is_empty() {
            return Ok(problem(
                StatusCode::BAD_REQUEST,
                &format!("unknown permissions: [{}]", unknown.join(", ")),
            ));
        }
        let keys: Vec<_> = self.keys.into_iter().collect();
        sqlx::query("DELETE FROM client_role_permissions WHERE client_id=$1 AND role_key=$2")
            .bind(client)
            .bind(key)
            .execute(&mut *tx)
            .await?;
        let inserted = sqlx::query(
            "INSERT INTO client_role_permissions(client_id,role_key,permission_key)
            SELECT $1,$2,unnest($3::text[])",
        )
        .bind(client)
        .bind(key)
        .bind(&keys)
        .execute(&mut *tx)
        .await;
        if let Err(error) = inserted {
            if error
                .as_database_error()
                .is_some_and(|e| e.is_foreign_key_violation() || e.is_unique_violation())
            {
                let name = crate::browser_prompt::quoted_string(client);
                return Ok(problem(
                    StatusCode::CONFLICT,
                    &format!("permission catalog of client {name} changed concurrently; retry"),
                ));
            }
            return Err(error);
        }
        crate::admin_audit::append_sorted_record(
            &mut tx,
            "client_role.permissions_set",
            self.actor,
            Some(("client_role", Some(&format!("{client}:{key}")))),
            &json!({"permissions":keys}),
            self.origin,
        )
        .await?;
        tx.commit().await?;
        Ok(Json(json!({"client_id":client,"role_key":key,"permissions":keys})).into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_count_submitted_items_before_deduplication() {
        let keys = vec!["read"; 256];
        let raw = RawValue::from_string(json!({"permissions":keys}).to_string()).unwrap();
        assert_eq!(input(&raw).unwrap(), BTreeSet::from(["read".into()]));
        let raw =
            RawValue::from_string(json!({"permissions":vec![false;257]}).to_string()).unwrap();
        assert_eq!(
            input(&raw).unwrap_err().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn diagnostic_rejects_nested_nonfinite_input() {
        let raw =
            serde_json::from_str::<&RawValue>(r#"{"permissions":[{"value":1e999}]}"#).unwrap();
        assert_eq!(
            input(raw).unwrap_err().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn catalog_lookup_preserves_unknown_keys_that_postgres_cannot_store() -> sqlx::Result<()>
    {
        use sqlx::Connection;
        let mut db = sqlx::PgConnection::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = db.begin().await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE client_permissions(client_id text,key text);
            INSERT INTO client_permissions VALUES('app','read'),('other','share');",
        )
        .execute(&mut *tx)
        .await?;
        let submitted = ["share", "read", "bad\0key"].map(String::from).into();
        assert_eq!(
            unknown_permissions(&mut tx, "app", &submitted).await?,
            [r#""bad\u0000key""#, r#""share""#]
        );
        tx.rollback().await
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn failed_audit_rolls_back_mapping_and_retry_commits() {
        use sqlx::Connection;
        let mut db = sqlx::PgConnection::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE client_permissions(client_id text,key text);
            CREATE TEMP TABLE client_role_permissions(client_id text,role_key text,permission_key text);
            CREATE TEMP TABLE audit_chain_head(id int PRIMARY KEY,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text CONSTRAINT refuse_audit CHECK(false),target_type text,target_id text,
                extra_metadata jsonb,ip_address inet,user_agent text,created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_type text,actor_client_id text,actor_email text);
            INSERT INTO client_permissions VALUES('app','read'),('app','write');
            INSERT INTO client_role_permissions VALUES('app','operator','read');").execute(&mut db).await.unwrap();
        let actor = Uuid::new_v4();
        let change = || Change {
            keys: BTreeSet::from(["write".into()]),
            actor: crate::admin_audit::Actor::User(Some((actor, None))),
            origin: SessionOrigin {
                ip: None,
                user_agent: None,
            },
        };
        assert!(
            change()
                .apply(db.begin().await.unwrap(), "app", "operator")
                .await
                .is_err()
        );
        let mapping = "SELECT permission_key FROM client_role_permissions";
        assert_eq!(
            sqlx::query_scalar::<_, String>(mapping)
                .fetch_all(&mut db)
                .await
                .unwrap(),
            ["read"]
        );
        sqlx::query("ALTER TABLE admin_action_logs DROP CONSTRAINT refuse_audit")
            .execute(&mut db)
            .await
            .unwrap();
        assert_eq!(
            change()
                .apply(db.begin().await.unwrap(), "app", "operator")
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(mapping)
                .fetch_all(&mut db)
                .await
                .unwrap(),
            ["write"]
        );
        let audit: (Uuid, Value) =
            sqlx::query_as("SELECT actor_user_id,extra_metadata FROM admin_action_logs")
                .fetch_one(&mut db)
                .await
                .unwrap();
        assert_eq!(audit, (actor, json!({"permissions":["write"]})));
        let delegated = Change {
            actor: crate::admin_audit::Actor::Client("app"),
            keys: BTreeSet::new(),
            ..change()
        };
        let result = delegated
            .apply(db.begin().await.unwrap(), "app", "operator")
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let cleared: (String, Option<Uuid>, Value) = sqlx::query_as(
            "SELECT actor_client_id,actor_user_id,extra_metadata FROM admin_action_logs WHERE actor_type='client'"
        ).fetch_one(&mut db).await.unwrap();
        assert_eq!(cleared, ("app".into(), None, json!({"permissions":[]})));
        assert!(
            sqlx::query_scalar::<_, String>(mapping)
                .fetch_all(&mut db)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
