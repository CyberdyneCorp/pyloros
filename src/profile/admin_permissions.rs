//! Operator access to a client's PostgreSQL permission catalog.
mod writes;
use super::*;
use crate::chain_settings::ChainSettings;
use axum::extract::Path;
use sqlx::Row;
pub(super) use writes::{create, remove};

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(client): Path<String>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    read_catalog(&state.blockchain, &mut tx, &client).await
}

async fn delegated_client(state: &Profile, headers: &HeaderMap) -> Result<String, Box<Response>> {
    use crate::{csrf::bearer, login_http::service_identity, token_revocation::VerifiedToken};
    let required = || service_identity::unauthorized("Service token required");
    let claims = bearer(headers)
        .and_then(|raw| state.verify.as_ref()?.service_claims(raw))
        .ok_or_else(required)?;
    let Ok(VerifiedToken::Service { client, id, .. }) =
        VerifiedToken::from_verified_claims(&claims)
    else {
        return Err(required());
    };
    service_identity::registration(&state.pool, &client, id, state.enforce)
        .await
        .map_err(|_| Box::new(internal()))?
        .map_err(service_identity::unauthorized)?;
    if !claims["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .any(|scope| scope == "roles:manage")
    {
        return Err(Box::new(crate::login_http::problem(
            StatusCode::FORBIDDEN,
            "Insufficient scope: roles:manage required",
        )));
    }
    Ok(client)
}

pub(super) async fn delegated_list(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let client = match delegated_client(&state, &headers).await {
        Ok(client) => client,
        Err(error) => return *error,
    };
    let Ok(mut tx) = state.pool.begin().await else {
        return internal();
    };
    read_catalog(&state.blockchain, &mut tx, &client).await
}

async fn read_catalog(
    blockchain: &ChainSettings,
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
) -> Response {
    if let Some(chain) = blockchain.provider().await
        && chain.validate_signer().is_err()
    {
        return internal();
    }
    catalog(tx, client).await.unwrap_or_else(|_| internal())
}

async fn catalog(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
) -> Result<Response, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT p.key, p.description, p.created_at
         FROM oauth_clients c LEFT JOIN client_permissions p ON p.client_id=c.client_id
         WHERE c.active AND c.client_id=$1 ORDER BY p.key",
    )
    .bind(client)
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() {
        return Ok(unknown_client(client));
    }
    let mut permissions = Vec::new();
    for row in rows {
        if let Some(key) = row.try_get::<Option<String>, _>("key")? {
            permissions.push(json!({
                "key": key,
                "client_id": client,
                "description": row.try_get::<Option<String>, _>("description")?,
                "created_at": timestamp(row.try_get("created_at")?)
            }));
        }
    }
    Ok(Json(json!({"client_id":client,"permissions":permissions})).into_response())
}

pub(super) fn unknown_client(client: &str) -> Response {
    let name = crate::browser_prompt::quoted_string(client);
    crate::login_http::problem(
        StatusCode::NOT_FOUND,
        &format!("unknown OAuth client {name}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn catalog_rejects_an_invalid_deployment_signer_before_lookup() {
        let settings = ChainSettings::default();
        settings
            .update(crate::chain_settings::Update {
                enabled: Some(true),
                rpc_url: Some("http://localhost".into()),
                identity_contract_address: Some("deployment".into()),
                private_key: Some(zeroize::Zeroizing::new("invalid".into())),
                ..Default::default()
            })
            .await;
        let deployment = ChainSettings::with_deployment(settings.provider().await.unwrap());
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE oauth_clients (client_id text, active boolean);
                       CREATE TEMP TABLE client_permissions (client_id text, key text, description text, created_at timestamptz);")
            .execute(&mut *tx).await.unwrap();
        assert_eq!(
            read_catalog(&deployment, &mut tx, "missing").await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            read_catalog(&ChainSettings::default(), &mut tx, "missing")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn permission_rows_belong_to_one_active_client() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE oauth_clients(client_id text, active boolean);
             CREATE TEMP TABLE client_permissions(client_id text, key text, description text, created_at timestamptz DEFAULT now());
             INSERT INTO oauth_clients VALUES ('first',true), ('second',true), ('unused',true);
             INSERT INTO client_permissions(client_id,key) VALUES ('second','other'), ('first','write'), ('first','read');"
        ).execute(&mut *tx).await.unwrap();

        for (client, expected) in [("first", vec!["read", "write"]), ("unused", vec![])] {
            let response = catalog(&mut tx, client).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let data: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(data["client_id"], client);
            let keys: Vec<_> = data["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["key"].as_str().unwrap())
                .collect();
            assert_eq!(keys, expected);
        }

        sqlx::query("UPDATE oauth_clients SET active=false WHERE client_id='first'")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            catalog(&mut tx, "first").await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }
}
