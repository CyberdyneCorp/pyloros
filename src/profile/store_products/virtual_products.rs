//! Audited updates to the product directory.
use super::*;
use futures_util::StreamExt;
use sqlx::Row;

#[derive(Deserialize)]
pub(super) struct ProductPath {
    key: Option<String>,
}

#[derive(Default)]
struct Input {
    key: Option<String>,
    name: Option<String>,
    description: Option<String>,
    active: Option<bool>,
    submitted: Vec<&'static str>,
}

fn input(model: Value, create: bool) -> Result<Input, Vec<Value>> {
    let body = admin_fields::object(&model)?;
    let mut fields = admin_fields::Fields {
        body,
        issues: Vec::new(),
    };
    let key = create
        .then(|| fields.string("key", Some(64), true))
        .flatten();
    let name = if create || body.get("name").is_some_and(|v| !v.is_null()) {
        fields
            .string("name", Some(128), true)
            .map(|name| admin_fields::trimmed(&name).to_owned())
    } else {
        None
    };
    let description = fields.string("description", Some(1024), false);
    let active = body
        .get("active")
        .filter(|v| !v.is_null())
        .map(|_| fields.boolean("active"));
    if !fields.issues.is_empty() {
        return Err(fields.issues);
    }
    let submitted = ["active", "description", "name"]
        .into_iter()
        .filter(|key| body.contains_key(*key))
        .collect();
    Ok(Input {
        key,
        name,
        description,
        active,
        submitted,
    })
}

pub(super) async fn deactivate(
    State(state): State<Arc<Profile>>,
    Path(key): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    use axum::body::HttpBody;
    if !body.is_end_stream() {
        // Keep an HTTP/1 upload readable after sending the response.
        tokio::spawn(async move {
            let mut chunks = body.into_data_stream();
            while let Some(Ok(_)) = chunks.next().await {}
        });
    }
    if method != Method::DELETE {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("PATCH"));
        return response;
    }
    let (tx, user, email) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    let edit = Input {
        active: Some(false),
        ..Default::default()
    };
    persist(
        tx,
        (user, email),
        Some(key),
        edit,
        true,
        origin(&state, &headers, peer),
    )
    .await
    .unwrap_or_else(|_| internal())
}

pub(super) async fn edit(
    State(state): State<Arc<Profile>>,
    Path(path): Path<ProductPath>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match fields::document(&headers, &bytes) {
        Ok(raw) => raw,
        Err(e) => return *e,
    };
    let (tx, user, email) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    let Some(raw) = raw else { return internal() };
    let creating = path.key.is_none();
    let keys = if creating {
        ["key", "name", "description"]
    } else {
        ["name", "description", "active"]
    };
    let edit = match fields::validate_scalar_document(&raw, &keys, |model| input(model, creating)) {
        Ok(data) => data,
        Err(e) => return *e,
    };
    persist(
        tx,
        (user, email),
        path.key,
        edit,
        false,
        origin(&state, &headers, peer),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn persist(
    mut tx: Transaction<'_, Postgres>,
    (user, email): (Uuid, Option<String>),
    path: Option<String>,
    input: Input,
    deactivate: bool,
    origin: SessionOrigin<'_>,
) -> sqlx::Result<Response> {
    let (key, action, meta, response) = if let Some(key) = path {
        let Some(item) = update(&mut tx, &key, &input).await? else {
            return Ok(problem(StatusCode::NOT_FOUND, "Product not found"));
        };
        if deactivate {
            (
                key,
                "product.deactivate",
                json!({}),
                StatusCode::NO_CONTENT.into_response(),
            )
        } else {
            (
                key,
                "product.update",
                json!({"changed_fields":input.submitted}),
                Json(item).into_response(),
            )
        }
    } else {
        let key = admin_fields::trimmed(input.key.as_deref().expect("validated key"));
        if !valid_key(key) {
            return Ok(problem(
                StatusCode::BAD_REQUEST,
                "product keys must match ^[a-z0-9][a-z0-9._-]{0,63}$ and must not start with 'cyb_'",
            ));
        }
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM products WHERE key=$1)")
            .bind(key)
            .fetch_one(&mut *tx)
            .await?;
        if exists {
            return Ok(problem(
                StatusCode::CONFLICT,
                &format!("product '{key}' already exists"),
            ));
        }
        let row = sqlx::query(
            "INSERT INTO products(key,name,description,active) VALUES($1,$2,$3,true) RETURNING *",
        )
        .bind(key)
        .bind(&input.name)
        .bind(&input.description)
        .fetch_one(&mut *tx)
        .await?;
        (
            key.to_owned(),
            "product.create",
            json!({"name":input.name}),
            (StatusCode::CREATED, Json(catalog::item(&row)?)).into_response(),
        )
    };
    crate::admin_audit::append(
        &mut tx,
        action,
        Some((user, email.as_deref())),
        ("product", &key),
        meta,
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

fn valid_key(key: &str) -> bool {
    let initial = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    key.as_bytes().first().is_some_and(|b| initial(*b))
        && !key.starts_with("cyb_")
        && key
            .bytes()
            .all(|b| initial(b) || matches!(b, b'.' | b'-' | b'_'))
}

async fn update(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
    input: &Input,
) -> sqlx::Result<Option<Value>> {
    let Some(old) = sqlx::query("SELECT * FROM products WHERE key=$1")
        .bind(key)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let name = old.try_get::<String, _>("name")?;
    let active = old.try_get::<bool, _>("active")?;
    let description = old.try_get::<Option<String>, _>("description")?;
    let name = input.name.as_ref().filter(|n| **n != name);
    let active = input.active.filter(|a| *a != active);
    let replace_description =
        input.submitted.contains(&"description") && input.description != description;
    if name.is_none() && active.is_none() && !replace_description {
        return catalog::item(&old).map(Some);
    }
    let row=sqlx::query("UPDATE products SET name=coalesce($2,name), active=coalesce($3,active),
        description=CASE WHEN $4 THEN $5 ELSE description END, updated_at=now() WHERE key=$1 RETURNING *")
        .bind(key).bind(name).bind(active).bind(replace_description).bind(&input.description).fetch_one(&mut **tx).await?;
    catalog::item(&row).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_overflow_is_never_an_explicit_null_patch() {
        use serde_json::value::RawValue;
        for key in ["name", "description", "active"] {
            for (number, status) in [
                ("9".repeat(350), StatusCode::UNPROCESSABLE_ENTITY),
                ("1e400".into(), StatusCode::INTERNAL_SERVER_ERROR),
            ] {
                let raw = RawValue::from_string(format!(r#"{{"{key}":{number}}}"#)).unwrap();
                let result =
                    fields::validate_scalar_document(&raw, &[key], |body| input(body, false));
                assert_eq!(result.err().unwrap().status(), status);
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn patch_retains_an_omitted_description_and_timestamps_for_noops() -> sqlx::Result<()> {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE products(key text,name text,description text,active bool,created_at timestamptz,updated_at timestamptz);
            INSERT INTO products VALUES ('test','Name','Details',true,now(),now()-interval '1 day')").execute(&mut *tx).await?;
        let no_change = input(json!({"active":null,"name":" Name "}), false).unwrap();
        let before = update(&mut tx, "test", &Input::default()).await?.unwrap();
        assert_eq!(update(&mut tx, "test", &no_change).await?.unwrap(), before);
        let clear = input(json!({"description":null}), false).unwrap();
        let after = update(&mut tx, "test", &clear).await?.unwrap();
        assert_eq!(after["description"], Value::Null);
        assert_ne!(after["updated_at"], before["updated_at"]);
        assert_eq!(clear.submitted, ["description"]);
        Ok(())
    }
}
