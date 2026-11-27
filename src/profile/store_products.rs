//! Administrative mobile storefront product mappings.
mod catalog;
mod virtual_products;
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::fields};
use axum::{
    Extension,
    extract::{Path, RawQuery},
};

#[derive(Clone, Copy)]
struct Store {
    table: &'static str,
    id: &'static str,
    target: &'static str,
    duplicate: &'static str,
}

const APPLE: Store = Store {
    table: "apple_products",
    id: "app_store_product_id",
    target: "apple_product",
    duplicate: "App Store product already mapped",
};
const GOOGLE: Store = Store {
    table: "google_products",
    id: "google_product_id",
    target: "google_product",
    duplicate: "Play product already mapped",
};

pub(super) fn routes() -> Router<Arc<Profile>> {
    let mut routes = Router::new()
        .route(
            "/api/v1/admin/products",
            any(catalog::list).post(virtual_products::edit),
        )
        .route("/api/v1/admin/products/{key}", any(virtual_products::edit));
    for (path, store) in [
        ("/api/v1/admin/apple-products", APPLE),
        ("/api/v1/admin/google-products", GOOGLE),
    ] {
        routes = routes.merge(
            Router::new()
                .route(path, any(list).post(create))
                .route(&format!("{path}/{{id}}"), any(remove))
                .layer(Extension(store)),
        );
    }
    routes
}

type Item = (String, String, Option<String>, DateTime<Utc>);

impl Store {
    fn item(&self, (id, product, plan, created): Item) -> Value {
        json!({self.id:id, "product_key":product, "plan":plan, "created_at":timestamp(created)})
    }

    async fn page(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        page: i128,
        size: i64,
    ) -> sqlx::Result<Response> {
        let Some(offset) = (page - 1)
            .checked_mul(size.into())
            .and_then(|n| i64::try_from(n).ok())
        else {
            return Ok(internal());
        };
        let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {}", self.table))
            .fetch_one(&mut **tx)
            .await?;
        let sql = format!(
            "SELECT {id},product_key,plan,created_at FROM {table} ORDER BY {id} LIMIT $1 OFFSET $2",
            id = self.id,
            table = self.table
        );
        let rows = sqlx::query_as::<_, Item>(&sql)
            .bind(size)
            .bind(offset)
            .fetch_all(&mut **tx)
            .await?;
        let products: Vec<_> = rows.into_iter().map(|row| self.item(row)).collect();
        Ok(
            Json(json!({"total":total,"products":products,"page":page,"page_size":size}))
                .into_response(),
        )
    }
}

async fn list(
    State(state): State<Arc<Profile>>,
    Extension(store): Extension<Store>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if method != Method::GET {
        return passkeys::post_required();
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    let params =
        url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes()).collect();
    let mut issues = Vec::new();
    let (page, size) = crate::query::pagination(&params, 50, 200, &mut issues);
    if !issues.is_empty() {
        return passkeys::validation(issues);
    }
    store
        .page(&mut tx, page, size)
        .await
        .unwrap_or_else(|_| internal())
}

struct Mapping {
    id: String,
    product: String,
    plan: Option<String>,
}

fn mapping(body: Value, id_field: &str) -> Result<Mapping, Vec<Value>> {
    let body = admin_fields::object(&body)?;
    let mut fields = admin_fields::Fields {
        body,
        issues: Vec::new(),
    };
    let id = fields.string(id_field, Some(255), true);
    let product = fields.string("product_key", Some(64), true);
    let plan = fields.string("plan", Some(64), false);
    if !fields.issues.is_empty() {
        return Err(fields.issues);
    }
    Ok(Mapping {
        id: id.expect("validated identifier"),
        product: product.expect("validated product"),
        plan,
    })
}

async fn create(
    State(state): State<Arc<Profile>>,
    Extension(store): Extension<Store>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match fields::document(&headers, &bytes) {
        Ok(body) => body,
        Err(e) => return *e,
    };
    let actor = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    let Some(raw) = raw else {
        return internal();
    };
    let input =
        match fields::validate_scalar_document(&raw, &[store.id, "product_key", "plan"], |v| {
            mapping(v, store.id)
        }) {
            Ok(input) => input,
            Err(e) => return *e,
        };
    write(
        store,
        actor,
        Mutation::Create(input),
        origin(&state, &headers, peer),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn remove(
    State(state): State<Arc<Profile>>,
    Extension(store): Extension<Store>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if method != Method::DELETE {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
        return response;
    }
    let actor = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    write(
        store,
        actor,
        Mutation::Delete(id),
        origin(&state, &headers, peer),
    )
    .await
    .unwrap_or_else(|_| internal())
}

fn origin<'a>(state: &Profile, headers: &'a HeaderMap, peer: SocketAddr) -> SessionOrigin<'a> {
    SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    }
}

pub(super) async fn grantable(
    tx: &mut Transaction<'_, Postgres>,
    product: &str,
) -> sqlx::Result<bool> {
    use sqlx::Row;
    let client = sqlx::query(
        "SELECT active AND registration_source IS DISTINCT FROM 'dynamic' AS eligible,
        allowed_audiences::text,redirect_uris::text,post_logout_redirect_uris::text
        FROM oauth_clients WHERE client_id=$1",
    )
    .bind(product)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = client {
        for field in [
            "allowed_audiences",
            "redirect_uris",
            "post_logout_redirect_uris",
        ] {
            if let Some(raw) = row.try_get::<Option<&str>, _>(field)? {
                crate::stored_json::validate_client_set(raw)?;
            }
        }
        return row.try_get("eligible");
    }
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM products WHERE key=$1 AND active)")
        .bind(product)
        .fetch_one(&mut **tx)
        .await
}

enum Mutation {
    Create(Mapping),
    Delete(String),
}

async fn write(
    store: Store,
    (mut tx, user, email): (Transaction<'_, Postgres>, Uuid, Option<String>),
    mutation: Mutation,
    origin: SessionOrigin<'_>,
) -> sqlx::Result<Response> {
    let (id, action, metadata, response) = match mutation {
        Mutation::Create(m) => {
            if !grantable(&mut tx, &m.product).await? {
                return Ok(problem(
                    StatusCode::BAD_REQUEST,
                    "Unknown or inactive product",
                ));
            }
            if exists(&mut tx, store, &m.id).await? {
                return Ok(problem(StatusCode::CONFLICT, store.duplicate));
            }
            let sql = format!(
                "INSERT INTO {table}({id},product_key,plan) VALUES($1,$2,$3) RETURNING {id},product_key,plan,created_at",
                table = store.table,
                id = store.id
            );
            let row = sqlx::query_as(&sql)
                .bind(&m.id)
                .bind(&m.product)
                .bind(&m.plan)
                .fetch_one(&mut *tx)
                .await?;
            (
                m.id,
                "create",
                json!({"product_key":m.product,"plan":m.plan}),
                (StatusCode::CREATED, Json(store.item(row))).into_response(),
            )
        }
        Mutation::Delete(id) => {
            if !exists(&mut tx, store, &id).await? {
                return Ok(problem(StatusCode::NOT_FOUND, "Mapping not found"));
            }
            sqlx::query(&format!(
                "DELETE FROM {} WHERE {}=$1",
                store.table, store.id
            ))
            .bind(&id)
            .execute(&mut *tx)
            .await?;
            (
                id,
                "delete",
                json!({}),
                StatusCode::NO_CONTENT.into_response(),
            )
        }
    };
    crate::admin_audit::append(
        &mut tx,
        &format!("{}.{action}", store.target),
        Some((user, email.as_deref())),
        (store.target, &id),
        metadata,
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

async fn exists(tx: &mut Transaction<'_, Postgres>, store: Store, id: &str) -> sqlx::Result<bool> {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT FROM {} WHERE {}=$1)",
        store.table, store.id
    ))
    .bind(id)
    .fetch_one(&mut **tx)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn registered_clients_take_precedence_over_virtual_products() -> sqlx::Result<()> {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE oauth_clients(client_id text,active bool,registration_source text,allowed_audiences jsonb,redirect_uris jsonb,post_logout_redirect_uris jsonb);
                       CREATE TEMP TABLE products(key text,active bool);
                       INSERT INTO oauth_clients VALUES ('disabled',false,'admin'),('dynamic',true,'dynamic'),('client',true,'admin');
                       INSERT INTO products VALUES ('virtual',true),('disabled',true),('dynamic',true),('inactive',false);")
            .execute(&mut *tx).await?;
        for (key, expected) in [
            ("virtual", true),
            ("disabled", false),
            ("dynamic", false),
            ("client", true),
            ("inactive", false),
            ("unknown", false),
        ] {
            assert_eq!(grantable(&mut tx, key).await?, expected, "{key}");
        }
        sqlx::query("UPDATE oauth_clients SET allowed_audiences='[[1]]' WHERE client_id='client'")
            .execute(&mut *tx)
            .await?;
        assert!(grantable(&mut tx, "client").await.is_err());
        Ok(())
    }
}
