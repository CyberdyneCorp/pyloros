//! Operator assignment of an existing client role.
use super::*;
use crate::{
    grant_response::SessionOrigin,
    login_http::problem,
    request_json::{fields, iam_document},
};
use serde_json::value::RawValue;

fn input(path: &str, raw: &RawValue, owner: Option<&str>) -> Result<Assignment, Box<Response>> {
    let submitted = fields::object_fields(raw)?;
    let value = fields::project_scalars(
        raw,
        &submitted,
        &["client_id", "role_key", "organization_id"],
    );
    let path_input = serde_json::value::to_raw_value(path).expect("string is JSON");
    let user = crate::query::path_uuid(path, "user_id");
    let mut issues = vec![];
    if let Err(issue) = &user {
        issues.push((issue.clone(), path_input.as_ref()));
    }
    match admin_fields::object_field(&value) {
        Ok(body) => {
            let mut model = admin_fields::Fields {
                body,
                issues: Vec::new(),
            };
            let client = owner
                .map(str::to_owned)
                .or_else(|| model.string("client_id", Some(64), true));
            let key = model.string("role_key", Some(48), true);
            let org = match body.get("organization_id") {
                Some(Value::String(text)) => {
                    crate::query::uuid_field(text, "body", "organization_id").map(Some)
                }
                None => Ok(None),
                Some(Value::Null) if submitted["organization_id"].get() == "null" => Ok(None),
                _ => Err(
                    json!({"type":"uuid_type","loc":["body","organization_id"],"msg":"UUID input should be a string, bytes or UUID object"}),
                ),
            };
            if let Err(issue) = &org {
                model.issues.push(issue.clone());
            }
            for issue in model.issues {
                let original = issue["loc"][1]
                    .as_str()
                    .and_then(|k| submitted.get(k))
                    .copied()
                    .unwrap_or(raw);
                issues.push((issue, original));
            }
            if let (Ok(user), Some(client), Some(key), Ok(org)) = (user, client, key, org)
                && issues.is_empty()
            {
                return Ok(Assignment {
                    user,
                    client,
                    key,
                    org,
                });
            }
        }
        Err(issue) => issues.push((issue, raw)),
    }
    Err(fields::invalid(issues))
}

pub(in crate::profile) async fn grant<const DELEGATED: bool>(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match iam_document::document(&headers, &bytes) {
        Ok(body) => body,
        Err(error) => return *error,
    };
    let (tx, caller) = match delegated::RoleCaller::authorize(&state, &headers, DELEGATED).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let Ok(chain) = authority(&state).await else {
        return internal();
    };
    let Some(body) = body else { return internal() };
    let grant = match input(&path, &body, caller.client_id()) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    grant
        .apply(tx, &state, chain, caller.actor(), origin)
        .await
        .unwrap_or_else(|_| internal())
}

impl Assignment {
    async fn apply(
        &self,
        mut tx: Transaction<'_, Postgres>,
        state: &Profile,
        chain: Option<crate::chain_settings::Chain>,
        actor: crate::admin_audit::Actor<'_>,
        origin: SessionOrigin<'_>,
    ) -> Result<Response, sqlx::Error> {
        if let Some(error) = self.check_target(&mut tx).await? {
            return Ok(error);
        }
        if let Some(chain) = chain {
            let edit = MembershipEdit::Grant {
                delegated: matches!(actor, crate::admin_audit::Actor::Client(_)),
            };
            if let Err(error) = self.change_membership(&mut tx, &chain, edit, state).await? {
                return Ok(*error);
            }
            return self.finish(tx, state, false, actor, origin).await;
        }
        let name = format!("rp:{}:{}", self.client, self.key);
        if global_key(&self.client, &name).is_none() {
            return Ok(missing_role(&self.client, &self.key));
        }
        let group = sqlx::query_as::<_, (Uuid, Option<String>)>(
            "SELECT id, description FROM iam_groups
             WHERE name=$1 ORDER BY created_at,id LIMIT 1 FOR KEY SHARE",
        )
        .bind(&name)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((mut id, description)) = group else {
            return Ok(missing_role(&self.client, &self.key));
        };
        if let Some(org) = self.org {
            if !self.is_member(&mut tx, org).await? {
                return Ok(not_member());
            }
            id = scoped_group(&mut tx, &format!("{name}@{org}"), description.as_deref()).await?;
        }
        if state.registration.hooks && !self.queue_hook(&mut tx, "role_granted").await? {
            return Ok(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Role grant hook dispatcher unavailable",
            ));
        }
        let (identity, created) = identity(&mut tx, self.user).await?;
        sqlx::query(
            "INSERT INTO iam_group_members(group_id,identity_id) VALUES($1,$2)
             ON CONFLICT(group_id,identity_id) DO NOTHING",
        )
        .bind(id)
        .bind(identity)
        .execute(&mut *tx)
        .await?;
        self.finish(tx, state, created, actor, origin).await
    }

    pub(super) async fn is_member(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        org: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let membership = sqlx::query_scalar::<_, Uuid>(
            "SELECT o.id FROM organizations o JOIN user_organizations m ON o.id=m.organization_id
             WHERE o.id=$1 AND o.is_active AND m.user_id=$2 FOR SHARE OF o,m",
        )
        .bind(org)
        .bind(self.user)
        .fetch_optional(&mut **tx)
        .await?;
        Ok(membership.is_some())
    }

    async fn finish(
        &self,
        mut tx: Transaction<'_, Postgres>,
        state: &Profile,
        created: bool,
        actor: crate::admin_audit::Actor<'_>,
        origin: SessionOrigin<'_>,
    ) -> Result<Response, sqlx::Error> {
        let target = self.user.to_string();
        let item = self.metadata();
        if state.registration.webhooks {
            let mut data = item.clone();
            data["user_id"] = json!(self.user);
            registration::enqueue_event(&mut tx, "role.granted", data, Utc::now()).await?;
        }
        if created {
            crate::admin_audit::append_actor_record(
                &mut tx,
                "iam_identity.create",
                actor,
                Some(("user", Some(&target))),
                json!({"reason":"role_grant"}),
                origin,
            )
            .await?;
        }
        crate::admin_audit::append_actor_record(
            &mut tx,
            "client_role.grant",
            actor,
            Some(("user", Some(&target))),
            item.clone(),
            origin,
        )
        .await?;
        tx.commit().await?;
        Ok((StatusCode::CREATED, Json(item)).into_response())
    }
}

pub(super) fn not_member() -> Response {
    problem(StatusCode::CONFLICT, "user is not a member of organization")
}

async fn scoped_group(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    description: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    if let Some(id) = sqlx::query_scalar(
        "SELECT id FROM iam_groups WHERE name=$1 ORDER BY created_at,id LIMIT 1 FOR KEY SHARE",
    )
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?
    {
        return Ok(id);
    }
    sqlx::query_scalar("INSERT INTO iam_groups(id,name,description) VALUES($1,$2,$3) RETURNING id")
        .bind(Uuid::new_v4())
        .bind(name)
        .bind(description)
        .fetch_one(&mut **tx)
        .await
}

async fn identity(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<(Uuid, bool), sqlx::Error> {
    if let Some(id) = sqlx::query_scalar("SELECT id FROM iam_identities WHERE user_id=$1")
        .bind(user)
        .fetch_optional(&mut **tx)
        .await?
    {
        return Ok((id, false));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO iam_identities(id,user_id) VALUES($1,$2)")
        .bind(id)
        .bind(user)
        .execute(&mut **tx)
        .await?;
    Ok((id, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegated_grant_uses_the_verified_client_and_preserves_organization_scope() {
        let user = Uuid::new_v4();
        let org = Uuid::new_v4();
        let raw = serde_json::value::to_raw_value(&json!({
            "client_id":"other", "role_key":"staff", "organization_id":org,
        }))
        .unwrap();
        let grant = input(&user.to_string(), &raw, Some("app")).unwrap();
        assert_eq!(grant.client, "app");
        assert_eq!(grant.user, user);
        assert_eq!(grant.org, Some(org));
    }

    #[test]
    fn invalid_organization_input_cannot_become_a_global_grant() {
        let path = Uuid::new_v4().to_string();
        let overflow = RawValue::from_string(
            r#"{"client_id":"c","role_key":"read","organization_id":1e999}"#.to_owned(),
        )
        .unwrap();
        let Err(error) = input(&path, &overflow, None) else {
            panic!("invalid organization accepted");
        };
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        for value in ["123456789012345678901234567890", "{}", "[]", "false"] {
            let text =
                format!(r#"{{"client_id":"c","role_key":"read","organization_id":{value}}}"#);
            let body = RawValue::from_string(text).unwrap();
            assert!(input(&path, &body, None).is_err());
        }
        let body = RawValue::from_string(
            r#"{"client_id":"c","role_key":"read","organization_id":null}"#.to_owned(),
        )
        .unwrap();
        assert!(input(&path, &body, None).unwrap().org.is_none());
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn retries_share_one_identity_and_scoped_group() {
        let db = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = db.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE iam_identities(id uuid, user_id uuid);
            CREATE TEMP TABLE iam_groups(id uuid,name text,description text,created_at timestamptz DEFAULT now());")
            .execute(&mut *tx).await.unwrap();
        let user = Uuid::new_v4();
        let (id, new) = identity(&mut tx, user).await.unwrap();
        assert!(new);
        assert_eq!(identity(&mut tx, user).await.unwrap(), (id, false));
        let group = scoped_group(&mut tx, "org-group", Some("label"))
            .await
            .unwrap();
        assert_eq!(
            group,
            scoped_group(&mut tx, "org-group", None).await.unwrap()
        );
    }
}
