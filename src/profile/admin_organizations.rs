//! Organization directory and user memberships for operators.
use super::*;
use axum::extract::Path;
mod assignment;
mod catalog;
mod creation;
mod edit;
mod input;
mod metadata;
mod removal;
pub(super) use assignment::assign;
pub(super) use catalog::list;
pub(super) use creation::create;
pub(super) use edit::{deactivate, edit};
pub(super) use removal::remove;

pub(super) async fn memberships(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (mut tx, user) = match target(&state, method, &headers, &raw, "user_id").await {
        Ok(target) => target,
        Err(error) => return *error,
    };
    read(&mut tx, user).await.unwrap_or_else(|_| internal())
}

async fn target(
    state: &Profile,
    method: Method,
    headers: &HeaderMap,
    raw: &str,
    field: &str,
) -> Result<(Transaction<'static, Postgres>, Uuid), Box<Response>> {
    if method != Method::GET {
        return Err(Box::new(crate::browser_http::method_not_allowed().await));
    }
    let (tx, _, _) = administrator::operator(state, headers).await?;
    let id = crate::query::path_uuid(raw, field)
        .map_err(|issue| Box::new(passkeys::validation(vec![issue])))?;
    Ok((tx, id))
}

pub(super) async fn detail(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    let (mut tx, id) = match target(&state, method, &headers, &raw, "org_id").await {
        Ok(target) => target,
        Err(error) => return *error,
    };
    let query = format!("SELECT {COLUMNS} FROM organizations o WHERE o.id=$1");
    match sqlx::query_as::<_, DirectoryRow>(&query)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .and_then(|row| row.map(item).transpose())
    {
        Ok(Some(record)) => Json(record).into_response(),
        Ok(None) => crate::login_http::problem(StatusCode::NOT_FOUND, "Organization not found"),
        Err(_) => internal(),
    }
}

async fn read(tx: &mut Transaction<'_, Postgres>, user: Uuid) -> Result<Response, sqlx::Error> {
    if !user_exists(tx, user).await? {
        return Ok(crate::login_http::problem(
            StatusCode::NOT_FOUND,
            &format!("user {user}"),
        ));
    }

    let query = format!(
        "SELECT {COLUMNS}
         FROM user_organizations m JOIN organizations o ON o.id=m.organization_id
         WHERE m.user_id=$1 AND o.is_active ORDER BY lower(o.short_name)"
    );
    let rows = sqlx::query_as::<_, DirectoryRow>(&query)
        .bind(user)
        .fetch_all(&mut **tx)
        .await?;
    Ok(Json(json!({"organizations": directory(rows)?})).into_response())
}

type DirectoryRow = (Value, String, DateTime<Utc>, DateTime<Utc>);

const COLUMNS: &str = "jsonb_build_object('id', o.id, 'name', o.name, 'short_name', o.short_name,
                 'domain_name', o.domain_name, 'github_login', o.github_login,
                 'description', o.description, 'is_active', o.is_active),
                o.extra_metadata::text, o.created_at, o.updated_at";

fn directory(rows: Vec<DirectoryRow>) -> Result<Vec<Value>, sqlx::Error> {
    rows.into_iter().map(item).collect()
}

fn item((mut item, metadata, created, updated): DirectoryRow) -> Result<Value, sqlx::Error> {
    item["metadata"] = metadata::strings(&metadata).map_err(|e| sqlx::Error::Decode(e.into()))?;
    item["created_at"] = json!(timestamp(created));
    item["updated_at"] = json!(timestamp(updated));
    Ok(item)
}

async fn user_exists(tx: &mut Transaction<'_, Postgres>, user: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM users WHERE id=$1)")
        .bind(user)
        .fetch_one(&mut **tx)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn memberships_are_explicit_active_and_user_scoped() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE users(id uuid, organization_id uuid);
             CREATE TEMP TABLE organizations(id uuid, name text, short_name text,
                 domain_name text, github_login text, description text, is_active bool,
                 extra_metadata jsonb DEFAULT '{}', created_at timestamptz DEFAULT now(),
                 updated_at timestamptz DEFAULT now());
             CREATE TEMP TABLE user_organizations(user_id uuid, organization_id uuid);
             INSERT INTO organizations(id,name,is_active) VALUES
                (gen_random_uuid(),'primary',true),(gen_random_uuid(),'team',true),
                (gen_random_uuid(),'archived',false),(gen_random_uuid(),'foreign',true);",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users SELECT $1,id FROM organizations WHERE name='primary'")
            .bind(user)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_organizations SELECT CASE WHEN name='foreign' THEN gen_random_uuid() ELSE $1 END,id FROM organizations WHERE name<>'primary'")
            .bind(user).execute(&mut *tx).await.unwrap();
        let response = read(&mut tx, user).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let inventory: Value = serde_json::from_slice(&bytes).unwrap();
        let entries = inventory["organizations"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "team");
    }
}
