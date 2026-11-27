//! Management of a service client's relationship model.
use super::*;
use crate::{admin_audit, grant_response::SessionOrigin, login_http::problem};
mod check;
pub(super) use check::check;
mod model;
mod relationships;
pub(super) use relationships::write;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectRef {
    #[serde(rename = "type")]
    kind: String,
    id: String,
}

impl ObjectRef {
    fn valid(&self) -> bool {
        model::name(&self.kind) && (1..=512).contains(&self.id.len()) && !self.id.contains('\0')
    }
}

pub(super) async fn put_model(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(model): Json<model::Model>,
) -> Response {
    let (client, registration) = match caller(&state, &headers, "rebac:manage").await {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    if let Err(message) = model.validate() {
        return problem(StatusCode::UNPROCESSABLE_ENTITY, message);
    }
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    replace(&state.pool, &client, registration, &model, origin)
        .await
        .unwrap_or_else(|_| internal())
}

async fn caller(
    state: &Profile,
    headers: &HeaderMap,
    scope: &str,
) -> Result<(String, Uuid), Box<Response>> {
    let Some(claims) =
        crate::csrf::bearer(headers).and_then(|raw| state.verify.as_ref()?.service_claims(raw))
    else {
        return Err(crate::login_http::service_identity::unauthorized(
            "Service token required",
        ));
    };
    let client = delegated::scoped_client(state, &claims, scope).await?;
    let Some(registration) = claims["rebac_client_id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return Err(crate::login_http::service_identity::unauthorized(
            "Relationship token required",
        ));
    };
    Ok((client, registration))
}

async fn management_transaction(
    pool: &PgPool,
    client: &str,
    registration: Uuid,
) -> Result<Transaction<'static, Postgres>, Box<Response>> {
    let mut tx = pool.begin().await.map_err(|_| Box::new(internal()))?;
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE client_id=$1 AND id=$2 AND active AND registration_source='admin' AND client_type='confidential'
         AND 'rebac:manage'=ANY(regexp_split_to_array(allowed_scopes,'[[:space:]]+')) FOR UPDATE",
    )
    .bind(client)
    .bind(registration)
    .fetch_optional(&mut *tx)
    .await.map_err(|_| Box::new(internal()))?;
    if owner.is_none() {
        return Err(Box::new(problem(
            StatusCode::FORBIDDEN,
            "Relationship management grant required",
        )));
    };
    let ready: bool =
        sqlx::query_scalar("SELECT to_regclass('pyloros_relationship_models') IS NOT NULL")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| Box::new(internal()))?;
    if !ready {
        return Err(Box::new(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Relationship storage unavailable",
        )));
    }
    Ok(tx)
}

async fn replace(
    pool: &PgPool,
    client: &str,
    registration: Uuid,
    model: &model::Model,
    origin: SessionOrigin<'_>,
) -> sqlx::Result<Response> {
    let mut tx = match management_transaction(pool, client, registration).await {
        Ok(tx) => tx,
        Err(response) => return Ok(*response),
    };
    let owner = registration;
    let model = sqlx::types::Json(model);
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS (
           SELECT 1 FROM pyloros_user_relationships WHERE client_id=$1
           AND NOT coalesce(($2::jsonb->'types'->object_type->'relations'->relation) ? 'user',false)
           UNION ALL
           SELECT 1 FROM pyloros_object_relationships WHERE client_id=$1
           AND NOT coalesce(($2::jsonb->'types'->object_type->'relations'->relation) ? subject_type,false)
         )",
    ).bind(owner).bind(model).fetch_one(&mut *tx).await?;
    if conflict {
        return Ok(problem(
            StatusCode::CONFLICT,
            "Stored relationships conflict with the proposed model",
        ));
    }
    let changed = sqlx::query(
        "INSERT INTO pyloros_relationship_models(client_id,model) VALUES($1,$2)
        ON CONFLICT(client_id) DO UPDATE SET model=excluded.model
        WHERE pyloros_relationship_models.model IS DISTINCT FROM excluded.model",
    )
    .bind(owner)
    .bind(model)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 0 {
        admin_audit::append_actor_record(
            &mut tx,
            "rebac.model.put",
            admin_audit::Actor::Client(client),
            Some(("relationship_model", Some(client))),
            json!({}),
            origin,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn replacement_preserves_both_kinds_of_relationship_and_requires_a_live_grant()
    -> sqlx::Result<()> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE oauth_clients(id uuid,client_id text,registration_source text,
            active boolean,allowed_scopes text,client_type text);
            CREATE TEMP TABLE pyloros_relationship_models(client_id uuid PRIMARY KEY,model jsonb);
            CREATE TEMP TABLE pyloros_user_relationships(client_id uuid,object_type text,relation text);
            CREATE TEMP TABLE pyloros_object_relationships(client_id uuid,object_type text,relation text,subject_type text);")
            .execute(&pool).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO oauth_clients VALUES($1,'example','admin',true,'rebac:manage','confidential')")
            .bind(id).execute(&pool).await?;
        let model: model::Model = serde_json::from_value(json!({"types":{}})).unwrap();
        let call = |registration| {
            replace(
                &pool,
                "example",
                registration,
                &model,
                SessionOrigin {
                    ip: None,
                    user_agent: None,
                },
            )
        };
        assert_eq!(call(Uuid::new_v4()).await?.status(), StatusCode::FORBIDDEN);
        sqlx::query("INSERT INTO pyloros_user_relationships VALUES($1,'document','reader')")
            .bind(id)
            .execute(&pool)
            .await?;
        assert_eq!(call(id).await?.status(), StatusCode::CONFLICT);
        sqlx::query("TRUNCATE pyloros_user_relationships")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO pyloros_object_relationships VALUES($1,'document','parent','team')",
        )
        .bind(id)
        .execute(&pool)
        .await?;
        assert_eq!(call(id).await?.status(), StatusCode::CONFLICT);
        sqlx::query("UPDATE oauth_clients SET allowed_scopes='rebac:check'")
            .execute(&pool)
            .await?;
        assert_eq!(call(id).await?.status(), StatusCode::FORBIDDEN);
        Ok(())
    }
}
