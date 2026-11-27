//! End the authenticated account's sessions.
use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    token_http::{client_ip, header as value},
};
use chrono::Utc;

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::POST {
        let mut response =
            crate::login_http::problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return response;
    }
    let Some(id) = credential(&headers).and_then(|token| state.verify.as_ref()?.read(token)) else {
        return unauthorized();
    };
    if id.client_bound {
        return unauthorized();
    }
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    revoke(&state, id, origin, value(&headers, "x-request-id"))
        .await
        .unwrap_or_else(|_| internal())
}

async fn revoke(
    state: &Profile,
    id: Identity,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, &id).await? {
        return Ok(unauthorized());
    }
    let now = Utc::now();
    let (count, subject) = end_sessions(&mut tx, id.user, now).await?;
    write_activity(
        &mut *tx,
        AuditActivity::LogoffAll(count),
        subject,
        origin,
        request,
        now,
    )
    .await?;
    tx.commit().await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    state.cookies.clear(response.headers_mut(), now);
    Ok(response)
}

async fn end_sessions(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    now: DateTime<Utc>,
) -> Result<(u64, AuditSubject), sqlx::Error> {
    let count =
        sqlx::query("UPDATE sessions SET revoked_at=$2 WHERE user_id=$1 AND revoked_at IS NULL")
            .bind(user)
            .bind(now)
            .execute(&mut **tx)
            .await?
            .rows_affected();
    let (email, organization) = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
        "UPDATE users SET tokens_valid_after=GREATEST(tokens_valid_after,$2) WHERE id=$1
         RETURNING primary_email, organization_id",
    )
    .bind(user)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_default();
    Ok((
        count,
        AuditSubject {
            user: Some(user),
            email,
            organization,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn count_only_newly_revoked_sessions_for_the_authenticated_account() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users (id uuid, tokens_valid_after timestamptz, primary_email text, organization_id uuid);
                       CREATE TEMP TABLE sessions (user_id uuid, revoked_at timestamptz);")
            .execute(&mut *tx).await.unwrap();
        let user = Uuid::new_v4();
        let other = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id) VALUES ($1),($2)")
            .bind(user)
            .bind(other)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions VALUES ($1,NULL),($1,NULL),($1,now()),($2,NULL)")
            .bind(user)
            .bind(other)
            .execute(&mut *tx)
            .await
            .unwrap();
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        assert_eq!(end_sessions(&mut tx, user, now).await.unwrap().0, 2);
        assert_eq!(end_sessions(&mut tx, user, now).await.unwrap().0, 0);
        let live =
            sqlx::query_scalar::<_, Uuid>("SELECT user_id FROM sessions WHERE revoked_at IS NULL")
                .fetch_all(&mut *tx)
                .await
                .unwrap();
        assert_eq!(live, vec![other]);
        let cutoff = sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(
            "SELECT id,tokens_valid_after FROM users WHERE tokens_valid_after IS NOT NULL",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert_eq!(cutoff, vec![(user, now)]);
        tx.rollback().await.unwrap();
    }
}
