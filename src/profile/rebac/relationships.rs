//! Assign or withdraw one typed relationship under the calling service's model.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::profile) struct Edge {
    object: ObjectRef,
    relation: String,
    subject: ObjectRef,
}

impl Edge {
    fn validate(&self) -> Result<Option<Uuid>, &'static str> {
        if !self.object.valid()
            || self.object.kind == "user"
            || !model::name(&self.relation)
            || !self.subject.valid()
        {
            return Err("Invalid relationship identifier");
        }
        if self.subject.kind == "user" {
            return Uuid::parse_str(&self.subject.id)
                .map(Some)
                .map_err(|_| "Invalid user identifier");
        }
        Ok(None)
    }
}

pub(in crate::profile) async fn write(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Json(edge): Json<Edge>,
) -> Response {
    let (client, owner) = match caller(&state, &headers, "rebac:manage").await {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    let account = match edge.validate() {
        Ok(id) => id,
        Err(reason) => return problem(StatusCode::UNPROCESSABLE_ENTITY, reason),
    };
    let tx = match management_transaction(&state.pool, &client, owner).await {
        Ok(tx) => tx,
        Err(response) => return *response,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    edge.apply(tx, (&client, owner), account, method == Method::PUT, origin)
        .await
        .unwrap_or_else(|_| internal())
}

impl Edge {
    async fn apply(
        &self,
        mut tx: Transaction<'_, Postgres>,
        (client, owner): (&str, Uuid),
        account: Option<Uuid>,
        grant: bool,
        origin: SessionOrigin<'_>,
    ) -> sqlx::Result<Response> {
        if grant {
            let allowed: Option<bool> = sqlx::query_scalar(
                "SELECT coalesce((model->'types'->$2->'relations'->$3) ? $4,false)
                 FROM pyloros_relationship_models WHERE client_id=$1",
            )
            .bind(owner)
            .bind(&self.object.kind)
            .bind(&self.relation)
            .bind(&self.subject.kind)
            .fetch_optional(&mut *tx)
            .await?;
            match allowed {
                None => {
                    return Ok(problem(
                        StatusCode::CONFLICT,
                        "Install a relationship model first",
                    ));
                }
                Some(false) => {
                    return Ok(problem(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Relationship is not declared in the model",
                    ));
                }
                Some(true) => {}
            }
        }
        let changed = if let Some(user) = account {
            if grant
                && sqlx::query("SELECT id FROM users WHERE id=$1 FOR KEY SHARE")
                    .bind(user)
                    .fetch_optional(&mut *tx)
                    .await?
                    .is_none()
            {
                return Ok(problem(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Unknown relationship account",
                ));
            }
            self.user_write(&mut tx, owner, user, grant).await?
        } else {
            self.object_write(&mut tx, owner, grant).await?
        };
        if changed != 0 {
            // Bound the audit target and avoid retaining raw account or application object IDs.
            let subject = account.map(|id| id.to_string());
            let target = json!([
                owner,
                self.object.kind,
                self.object.id,
                self.relation,
                self.subject.kind,
                subject.as_ref().unwrap_or(&self.subject.id)
            ]);
            let key = crate::authorization_codes::digest(&target.to_string());
            admin_audit::append_actor_record(&mut tx,
                if grant {"rebac.relationship.put"} else {"rebac.relationship.delete"},
                admin_audit::Actor::Client(client), Some(("relationship",Some(&key))),
                json!({"object_type":self.object.kind,"relation":self.relation,"subject_type":self.subject.kind}),origin).await?;
        }
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    async fn user_write(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: Uuid,
        user: Uuid,
        grant: bool,
    ) -> sqlx::Result<u64> {
        let sql = if grant {
            "INSERT INTO pyloros_user_relationships(client_id,object_type,object_id,relation,user_id)
             VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING"
        } else {
            "DELETE FROM pyloros_user_relationships WHERE client_id=$1 AND object_type=$2 AND object_id=$3 AND relation=$4 AND user_id=$5"
        };
        Ok(sqlx::query(sql)
            .bind(owner)
            .bind(&self.object.kind)
            .bind(&self.object.id)
            .bind(&self.relation)
            .bind(user)
            .execute(&mut **tx)
            .await?
            .rows_affected())
    }

    async fn object_write(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: Uuid,
        grant: bool,
    ) -> sqlx::Result<u64> {
        let sql = if grant {
            "INSERT INTO pyloros_object_relationships(client_id,object_type,object_id,relation,subject_type,subject_id)
             VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING"
        } else {
            "DELETE FROM pyloros_object_relationships WHERE client_id=$1 AND object_type=$2 AND object_id=$3 AND relation=$4 AND subject_type=$5 AND subject_id=$6"
        };
        Ok(sqlx::query(sql)
            .bind(owner)
            .bind(&self.object.kind)
            .bind(&self.object.id)
            .bind(&self.relation)
            .bind(&self.subject.kind)
            .bind(&self.subject.id)
            .execute(&mut **tx)
            .await?
            .rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_relationship_and_its_audit_change_together() -> sqlx::Result<()> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE pyloros_relationship_models(client_id uuid,model jsonb);
            CREATE TEMP TABLE pyloros_object_relationships(client_id uuid,object_type text,object_id text,
                relation text,subject_type text,subject_id text, UNIQUE(client_id,object_type,object_id,relation,subject_type,subject_id));
            CREATE TEMP TABLE audit_chain_head(id int PRIMARY KEY,head_hash text);
            CREATE TEMP TABLE admin_action_logs(id uuid,action text CHECK(action <> 'rebac.relationship.delete'),
                target_type text,target_id text,extra_metadata jsonb,ip_address inet,user_agent text,
                created_at timestamptz,prev_hash text,row_hash text,actor_user_id uuid,actor_email text,
                actor_type text,actor_client_id text);").execute(&pool).await?;
        let owner = Uuid::new_v4();
        let edge: Edge = serde_json::from_value(json!({"object":{"type":"file","id":"1"},
            "relation":"parent","subject":{"type":"file","id":"2"}}))
        .unwrap();
        let model = json!({"types":{"file":{"relations":{"parent":["file"]}}}});
        sqlx::query("INSERT INTO pyloros_relationship_models VALUES($1,$2)")
            .bind(owner)
            .bind(model)
            .execute(&pool)
            .await?;
        let apply = |tx, grant| {
            edge.apply(
                tx,
                ("app", owner),
                None,
                grant,
                SessionOrigin {
                    ip: None,
                    user_agent: None,
                },
            )
        };
        for _ in 0..2 {
            assert_eq!(
                apply(pool.begin().await?, true).await?.status(),
                StatusCode::NO_CONTENT
            );
        }
        assert!(apply(pool.begin().await?, false).await.is_err());
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM pyloros_object_relationships),
            (SELECT count(*) FROM admin_action_logs)",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(counts, (1, 1));
        Ok(())
    }

    #[test]
    fn relationship_identifiers_observe_storage_byte_limits_and_typed_user_ids() {
        let mut edge: Edge = serde_json::from_value(json!({
            "object":{"type":"album","id":"é".repeat(256)}, "relation":"owner",
            "subject":{"type":"user","id":"00000000-0000-0000-0000-000000000001"}
        }))
        .unwrap();
        assert_eq!(edge.validate().unwrap(), Some(Uuid::from_u128(1)));
        edge.object.id.push('x');
        assert!(edge.validate().is_err());
        edge.object.id = "a".into();
        edge.subject.id = "opaque".into();
        assert!(edge.validate().is_err());
        edge.subject.kind = "team".into();
        assert_eq!(edge.validate().unwrap(), None);
    }
}
