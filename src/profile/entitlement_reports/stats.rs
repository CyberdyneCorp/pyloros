//! Count currently effective grant rows, including organization grants.
use super::*;
use std::collections::BTreeMap;

pub(super) async fn read(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    report(&mut tx)
        .await
        .map(|v| Json(v).into_response())
        .unwrap_or_else(|_| internal())
}

#[derive(Default, serde::Serialize)]
struct Product {
    product_key: String,
    product_name: String,
    total: i64,
    by_plan: BTreeMap<String, i64>,
    by_source: BTreeMap<String, i64>,
}

async fn report(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<Value> {
    let rows = sqlx::query_as::<_, (String, String, String, i64)>(
        "SELECT product_key,coalesce(nullif(plan,''),'—'),source,count(*)
        FROM entitlements WHERE status='active' AND (expires_at IS NULL OR expires_at>$1)
        GROUP BY 1,2,3",
    )
    .bind(Utc::now())
    .fetch_all(&mut **tx)
    .await?;
    let mut buckets = BTreeMap::<String, Product>::new();
    for (key, plan, source, count) in rows {
        let p = buckets.entry(key).or_default();
        p.total += count;
        *p.by_plan.entry(plan).or_default() += count;
        *p.by_source.entry(source).or_default() += count;
    }
    let mut products = Vec::with_capacity(buckets.len());
    for (key, mut p) in buckets {
        p.product_name = product_name(tx, &key).await?;
        p.product_key = key;
        products.push(p);
    }
    products.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then_with(|| a.product_key.cmp(&b.product_key))
    });
    Ok(json!({"products":products}))
}

async fn product_name(tx: &mut Transaction<'_, Postgres>, key: &str) -> sqlx::Result<String> {
    let client=sqlx::query("SELECT name,allowed_audiences::text,redirect_uris::text,post_logout_redirect_uris::text FROM oauth_clients WHERE client_id=$1")
        .bind(key).fetch_optional(&mut **tx).await?;
    if let Some(row) = client {
        for i in 1..=3 {
            if let Some(raw) = row.try_get::<Option<String>, _>(i)? {
                crate::stored_json::validate_client_set(&raw)?;
            }
        }
        return row.try_get("name");
    }
    Ok(sqlx::query_scalar("SELECT name FROM products WHERE key=$1")
        .bind(key)
        .fetch_optional(&mut **tx)
        .await?
        .unwrap_or_else(|| key.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn counts_rows_with_live_expiry_and_resolves_client_names_first() -> sqlx::Result<()> {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE entitlements(product_key text,plan text,source text,status text, expires_at timestamptz);
            CREATE TEMP TABLE oauth_clients(client_id text,name text,allowed_audiences jsonb,redirect_uris jsonb,post_logout_redirect_uris jsonb);
            CREATE TEMP TABLE products(key text,name text);
            INSERT INTO products VALUES ('app','Alternate');
            INSERT INTO oauth_clients(client_id,name) VALUES('app','Application');
            INSERT INTO entitlements VALUES ('app',NULL,'admin','active',NULL),('app','','stripe','active',NULL),
                ('app','old','admin','active',now()-interval '1 hour'),('app','old','apple','revoked',NULL),
                ('other','tier','google','active',now()+interval '1 day');").execute(&mut *tx).await?;
        let value = report(&mut tx).await?;
        assert_eq!(
            value["products"][0],
            json!({"product_key":"app","product_name":"Application","total":2,"by_plan":{"—":2},"by_source":{"admin":1,"stripe":1}})
        );
        assert_eq!(value["products"][1]["product_name"], "other");
        Ok(())
    }
}
