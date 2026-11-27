//! Replace an operator-managed role mapping and its audit event atomically.
use super::*;
use crate::grant_response::SessionOrigin;
use crate::login_http::problem;
use std::collections::BTreeSet;

pub(super) struct Change<'a> {
    keys: BTreeSet<String>,
    actor: Uuid,
    email: Option<String>,
    origin: SessionOrigin<'a>,
}

pub(in crate::profile) async fn put(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((client, key)): Path<(String, String)>,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match crate::request_json::fields::document(&headers, &bytes) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
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
        actor,
        email,
        origin,
    };
    catalog(
        &state,
        chain,
        tx,
        &client,
        Some(Target {
            key: &key,
            change: Some(change),
        }),
    )
    .await
    .unwrap_or_else(|_| internal())
}

use crate::request_json::fields::{FieldIssue, field_issue, validation_input};
use serde_json::value::RawValue;

fn invalid(detail: Vec<FieldIssue<'_>>) -> Box<Response> {
    #[derive(Serialize)]
    struct Errors<'a> {
        detail: Vec<FieldIssue<'a>>,
    }
    Box::new((StatusCode::UNPROCESSABLE_ENTITY, Json(Errors { detail })).into_response())
}

fn input(raw: &RawValue) -> Result<BTreeSet<String>, Box<Response>> {
    let (model, original) = validation_input(raw, "permissions")?;
    let fields =
        admin_fields::object_field(&model).map_err(|e| invalid(vec![field_issue(e, raw)]))?;
    let location = ["body", "permissions"];
    if !fields.contains_key("permissions") {
        return Err(invalid(vec![field_issue(
            json!({"type":"missing","loc":location,"msg":"Field required"}),
            raw,
        )]));
    }
    let Ok(items) = serde_json::from_str::<Vec<&RawValue>>(original.get()) else {
        return Err(invalid(vec![field_issue(
            json!({"type":"list_type","loc":location,"msg":"Input should be a valid list"}),
            original,
        )]));
    };
    let n = items.len();
    if n > 256 {
        return Err(invalid(vec![field_issue(
            json!({"type":"too_long","loc":location,"msg":format!("List should have at most 256 items after validation, not {n}"),"ctx":{"field_type":"List","max_length":"256","actual_length":n.to_string()}}),
            original,
        )]));
    }
    let mut keys = BTreeSet::new();
    let mut issues = Vec::new();
    for (i, item) in items.into_iter().enumerate() {
        match serde_json::from_str::<String>(item.get()) {
            Ok(key) => { keys.insert(key); }
            Err(_) => issues.push(field_issue(json!({"type":"string_type","loc":["body","permissions",i],"msg":"Input should be a valid string"}),item)),
        }
    }
    if issues.is_empty() {
        Ok(keys)
    } else {
        Err(invalid(issues))
    }
}

impl Change<'_> {
    pub(super) async fn apply(
        self,
        mut tx: Transaction<'_, Postgres>,
        client: &str,
        key: &str,
    ) -> Result<Response, sqlx::Error> {
        let known: Vec<String> =
            sqlx::query_scalar("SELECT key FROM client_permissions WHERE client_id=$1")
                .bind(client)
                .fetch_all(&mut *tx)
                .await?;
        let known = known.into_iter().collect::<BTreeSet<_>>();
        let unknown: Vec<_> = self
            .keys
            .difference(&known)
            .map(|s| crate::admin_audit::ascii_json(&json!(s)))
            .collect();
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
        crate::admin_audit::append(
            &mut tx,
            "client_role.permissions_set",
            Some((self.actor, self.email.as_deref())),
            ("client_role", &format!("{client}:{key}")),
            json!({"permissions":keys}),
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
            actor,
            email: None,
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
    }
}
