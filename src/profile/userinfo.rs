use super::*;
use crate::{csrf::bearer, id_tokens::profile_fields, login_http::problem};

fn unauthorized_bearer() -> Response {
    let mut response = problem(StatusCode::UNAUTHORIZED, "Invalid access token");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    if !state.oidc_enabled {
        return problem(StatusCode::NOT_FOUND, "OIDC disabled");
    }
    let identity =
        bearer(&headers).and_then(|raw| state.verify.as_ref()?.claims(raw)?.user_identity());
    let Some(identity) = identity else {
        return unauthorized_bearer();
    };
    let Ok(mut tx) = state.pool.begin().await else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "UserInfo unavailable");
    };
    match read(&mut tx, &identity, state.enforce).await {
        Ok(Some(doc)) => Json(doc).into_response(),
        Ok(None) => unauthorized_bearer(),
        Err(_) => problem(StatusCode::SERVICE_UNAVAILABLE, "UserInfo unavailable"),
    }
}

async fn read(
    tx: &mut Transaction<'_, Postgres>,
    id: &Identity,
    enforce: bool,
) -> Result<Option<Value>, sqlx::Error> {
    if enforce && revoked(tx, id).await? {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, (Option<String>, bool, Value)>(
        "SELECT primary_email, is_email_verified, extra_metadata FROM users WHERE id=$1 AND is_active",
    )
    .bind(id.user)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((email, verified, metadata)) = row else {
        return Ok(None);
    };
    let mut doc = json!({"sub":id.user});
    if let Some(email) = email.filter(|s| !s.is_empty()) {
        doc["email"] = json!(email);
        doc["email_verified"] = json!(verified);
    }
    profile_fields(&mut doc, &metadata);
    Ok(Some(doc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn client_bound_bearer_reads_current_active_account() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let user = Uuid::new_v4();
        let claims: Claims = serde_json::from_value(
            json!({"type":"access","sub":user,"jti":Uuid::new_v4(),"client_id":"dcr_fixture"}),
        )
        .unwrap();
        let identity = claims.user_identity().unwrap();
        assert!(claims.identity().is_none());
        sqlx::query("CREATE TEMP TABLE users(id uuid,primary_email text,is_email_verified boolean,extra_metadata jsonb,is_active boolean)").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO users VALUES ($1,NULL,false,$2,true)")
            .bind(user)
            .bind(json!({"name":"","full_name":"Test User"}))
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            read(&mut tx, &identity, false).await.unwrap(),
            Some(json!({"sub":user,"name":"Test User"}))
        );
        sqlx::query("UPDATE users SET is_active=false")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(read(&mut tx, &identity, false).await.unwrap(), None);
        tx.rollback().await.unwrap();
    }
}
