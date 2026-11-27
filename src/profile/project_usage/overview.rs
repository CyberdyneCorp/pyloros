use super::*;

pub(super) async fn list(tx: &mut Tx<'_>, page: Page) -> sqlx::Result<Response> {
    let since = Utc::now() - chrono::Duration::days(30);
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_clients")
        .fetch_one(&mut **tx)
        .await?;
    let clients = registry::page(tx, &page).await?;
    let ids: Vec<_> = clients.iter().map(|c| c.client_id.as_str()).collect();
    let mut projects = Vec::with_capacity(ids.len());
    if !ids.is_empty() {
        let entitled: HashMap<String, i64> = sqlx::query_as(
            "SELECT product_key,count(DISTINCT user_id) FROM entitlements
            WHERE product_key=ANY($1) AND status='active' GROUP BY product_key",
        )
        .bind(&ids)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .collect();
        let times: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT client_id,timestamptz_send(max(consumed_at)) FROM oidc_authorization_codes
            WHERE client_id=ANY($1) AND consumed_at IS NOT NULL GROUP BY client_id",
        )
        .bind(&ids)
        .fetch_all(&mut **tx)
        .await?;
        let last = times
            .into_iter()
            .map(|(id, t)| Ok((id, stamp(&t)?)))
            .collect::<sqlx::Result<HashMap<_, _>>>()?;
        let active: HashMap<String, i64> = sqlx::query_as(
            "SELECT client_id,count(DISTINCT user_id) FROM oidc_authorization_codes
            WHERE client_id=ANY($1) AND consumed_at >= $2 GROUP BY client_id",
        )
        .bind(&ids)
        .bind(since)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .collect();
        let users: HashMap<String,i64> = sqlx::query_as("SELECT project,count(DISTINCT user_id) FROM (
            SELECT product_key AS project,user_id FROM entitlements WHERE product_key=ANY($1) AND status='active'
            UNION ALL SELECT client_id,user_id FROM oidc_authorization_codes WHERE client_id=ANY($1) AND consumed_at IS NOT NULL
            ) AS usage GROUP BY project").bind(&ids).fetch_all(&mut **tx).await?.into_iter().collect();
        for client in clients {
            let id = client.client_id;
            projects.push(json!({"client_id":id,"name":client.name,"client_type":client.client_type,"active":client.active,
                "total_users":users.get(&id).copied().unwrap_or(0),"active_users":active.get(&id).copied().unwrap_or(0),
                "entitled_users":entitled.get(&id).copied().unwrap_or(0),"last_activity_at":last.get(&id)}));
        }
    }
    Ok(
        Json(json!({"projects":projects,"total":total,"page":page.number,"page_size":page.size}))
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn counts_accounts_once_across_grants_and_sign_ins() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE oauth_clients(client_id text, name text, client_type text, active bool,
            allowed_audiences jsonb,redirect_uris jsonb,post_logout_redirect_uris jsonb,created_at timestamptz,
            updated_at timestamptz,previous_secret_expires_at timestamptz,last_used_at timestamptz);
            CREATE TEMP TABLE entitlements(product_key text,user_id uuid,status text);
            CREATE TEMP TABLE oidc_authorization_codes(client_id text,user_id uuid,consumed_at timestamptz);
            INSERT INTO oauth_clients(client_id,name,client_type,active) VALUES ('console','Console','public',false);
            INSERT INTO entitlements VALUES ('console',null,'active'),('console',gen_random_uuid(),'active');
            INSERT INTO oidc_authorization_codes SELECT 'console',user_id,now() FROM entitlements WHERE user_id IS NOT NULL;
            INSERT INTO oidc_authorization_codes VALUES ('console',gen_random_uuid(),now()-interval '40 days'),
                ('console',gen_random_uuid(),null);")
            .execute(&mut *tx).await.unwrap();
        let response = list(
            &mut tx,
            Page {
                number: 1,
                size: 50,
            },
        )
        .await
        .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let item = &json["projects"][0];
        assert_eq!(item["total_users"], 2);
        assert_eq!(item["active_users"], 1);
        assert_eq!(item["entitled_users"], 1);
        assert_eq!(item["active"], false);
    }
}
