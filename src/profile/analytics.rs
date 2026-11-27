//! Administrative reports over the current PostgreSQL account and session data.
use super::*;
use axum::{Extension, extract::RawQuery};

#[derive(Clone, Copy)]
enum Report {
    Overview,
    Registrations,
    Methods,
    Activity,
}

#[derive(Clone)]
struct CalendarZone(Option<String>);

pub(super) fn routes() -> Router<Arc<Profile>> {
    let mut router = Router::new();
    for (path, report) in [
        ("/api/v1/admin/analytics/overview", Report::Overview),
        (
            "/api/v1/admin/analytics/registrations",
            Report::Registrations,
        ),
        ("/api/v1/admin/analytics/auth-methods", Report::Methods),
        ("/api/v1/admin/analytics/activity", Report::Activity),
    ] {
        router = router.route(path, any(read).layer(Extension(report)));
    }
    router.layer(Extension(CalendarZone(
        env::var("PYLOROS_REGISTRATION_TIME_ZONE").ok(),
    )))
}

async fn read(
    State(state): State<Arc<Profile>>,
    Extension(report): Extension<Report>,
    Extension(zone): Extension<CalendarZone>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(error) => return *error,
    };
    let result = match report {
        Report::Overview => overview(&mut tx).await,
        Report::Activity => activity(&mut tx, Utc::now()).await,
        Report::Methods => methods(&mut tx).await,
        Report::Registrations => {
            let days = match days(query.as_deref().unwrap_or_default()) {
                Ok(days) => days,
                Err(issue) => return passkeys::validation(vec![issue]),
            };
            sqlx::query_scalar(include_str!("analytics/registrations.sql"))
                .bind(days)
                .bind(zone.0.as_deref())
                .fetch_one(&mut *tx)
                .await
        }
    };
    result
        .map(|value| Json(value).into_response())
        .unwrap_or_else(|_| internal())
}

async fn count(tx: &mut Transaction<'_, Postgres>, sql: &str) -> sqlx::Result<i64> {
    sqlx::query_scalar(sql).fetch_one(&mut **tx).await
}

// Use successive reads so concurrent commits become visible at the same report boundaries.
async fn overview(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<Value> {
    let midnight = Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight")
        .and_utc();
    let mut data = serde_json::Map::new();
    for (name, sql) in [
        ("total_users", "SELECT count(*) FROM users"),
        ("active_users", "SELECT count(*) FROM users WHERE is_active"),
        (
            "email_verified_users",
            "SELECT count(*) FROM users WHERE is_email_verified",
        ),
    ] {
        data.insert(name.into(), count(tx, sql).await?.into());
    }
    for (name, days) in [
        ("users_today", 0),
        ("users_this_week", 7),
        ("users_this_month", 30),
    ] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE created_at >= $1")
            .bind(midnight - chrono::TimeDelta::days(days))
            .fetch_one(&mut **tx)
            .await?;
        data.insert(name.into(), n.into());
    }
    for (name, sql) in [
        (
            "active_sessions",
            "SELECT count(*) FROM sessions WHERE revoked_at IS NULL",
        ),
        ("total_hooks", "SELECT count(*) FROM hooks"),
        ("active_hooks", "SELECT count(*) FROM hooks WHERE is_active"),
    ] {
        data.insert(name.into(), count(tx, sql).await?.into());
    }
    Ok(Value::Object(data))
}

async fn methods(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<Value> {
    let users = count(tx, "SELECT count(*) FROM users").await?;
    sqlx::query_scalar(include_str!("analytics/methods.sql"))
        .bind(users)
        .fetch_one(&mut **tx)
        .await
}

async fn activity(tx: &mut Transaction<'_, Postgres>, now: DateTime<Utc>) -> sqlx::Result<Value> {
    let mut users = serde_json::Map::new();
    for (name, days) in [("active_24h", 1), ("active_7d", 7), ("active_30d", 30)] {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT user_id) FROM sessions
            WHERE revoked_at IS NULL AND last_used_at >= $1",
        )
        .bind(now - chrono::TimeDelta::days(days))
        .fetch_one(&mut **tx)
        .await?;
        users.insert(name.into(), n.into());
    }
    sqlx::query_scalar(include_str!("analytics/activity.sql"))
        .bind(now)
        .bind(Value::Object(users))
        .fetch_one(&mut **tx)
        .await
}

fn days(query: &str) -> Result<i32, Value> {
    url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| key == "days")
        .map(|(_, value)| value)
        .last()
        .map_or(Ok(30), |raw| {
            crate::query::bounded("days", &raw, Some(365)).map(|n| n as i32)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_uses_last_days_parameter_and_rejects_out_of_bounds() {
        assert_eq!(days("days=1&other=2&days=365.0").unwrap(), 365);
        assert_eq!(days("").unwrap(), 30);
        assert_eq!(days("days=366").unwrap_err()["type"], "less_than_equal");
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn registration_calendar_can_differ_from_the_connection_zone() -> sqlx::Result<()> {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE users(created_at timestamptz);
            INSERT INTO users VALUES (date_trunc('day',now(),'UTC') - interval '23 hours'),
                                     (date_trunc('day',now(),'UTC') - interval '18 hours');",
        )
        .execute(&mut *tx)
        .await?;
        for (zone, expected_buckets) in [("UTC", 1), ("America/Barbados", 2)] {
            let page: Value = sqlx::query_scalar(include_str!("analytics/registrations.sql"))
                .bind(30)
                .bind(zone)
                .fetch_one(&mut *tx)
                .await?;
            assert_eq!(page["total"], 2);
            assert_eq!(
                page["registrations"].as_array().unwrap().len(),
                expected_buckets
            );
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn expired_heartbeats_and_live_ages_use_their_own_populations() -> sqlx::Result<()> {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE sessions(user_id int,created_at timestamptz,last_used_at timestamptz,expires_at timestamptz,revoked_at timestamptz);
            INSERT INTO sessions VALUES
            (1,now()-interval '2 days',now()-interval '2 hours',now()+interval '1 hour',NULL),
            (1,now()-interval '4 days',now()-interval '2 days',now()+interval '1 hour',NULL),
            (2,now()-interval '20 days',now()-interval '15 days',now()-interval '1 hour',NULL),
            (3,now()-interval '1 day',now(),now()+interval '1 hour',now());")
            .execute(&mut *tx).await?;
        let data = activity(&mut tx, Utc::now()).await?;
        assert_eq!(data["active_24h"], 1);
        assert_eq!(data["active_7d"], 1);
        assert_eq!(data["active_30d"], 2);
        assert_eq!(data["live_sessions"], 2);
        assert_eq!(data["mean_session_age_s"], data["median_session_age_s"]);
        assert!(data["median_session_age_s"].as_i64().unwrap() >= 259200);
        Ok(())
    }
}
