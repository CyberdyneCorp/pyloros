//! Organization directory and user memberships for operators.
use super::*;
use axum::extract::Path;
mod addition;
mod catalog;
mod metadata;
pub(super) use addition::add;
pub(super) use catalog::list;

pub(super) async fn memberships(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let user = match crate::query::path_uuid(&raw, "user_id") {
        Ok(user) => user,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    read(&mut tx, user).await.unwrap_or_else(|_| internal())
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
    let mut organizations = Vec::with_capacity(rows.len());
    for (mut item, metadata, created, updated) in rows {
        item["metadata"] =
            metadata::strings(&metadata).map_err(|e| sqlx::Error::Decode(e.into()))?;
        item["created_at"] = json!(timestamp(created));
        item["updated_at"] = json!(timestamp(updated));
        organizations.push(item);
    }
    Ok(organizations)
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
