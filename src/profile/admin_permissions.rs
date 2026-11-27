//! Operator access to a client's PostgreSQL permission catalog.
use super::*;
use axum::extract::Path;
use sqlx::Row;

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
    if let Some(chain) = state.blockchain.membership_source().await
        && chain.validate_signer().is_err()
    {
        return internal();
    }
    catalog(&mut tx, &client)
        .await
        .unwrap_or_else(|_| internal())
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
