use super::*;
use sqlx::Row;

pub(super) struct Delivery {
    pub id: Uuid,
    pub subscription: Uuid,
    pub event: Uuid,
    pub body: String,
    pub url: String,
    pub attempts: i32,
    pub current: Vec<u8>,
    pub previous: Option<Vec<u8>>,
}

pub(super) async fn claim(
    pool: &PgPool,
    now: DateTime<Utc>,
    until: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<Delivery>> {
    let mut tx = pool.begin().await?;
    sqlx::query("WITH inactive AS (
        SELECT d.id FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id=d.subscription_id
        WHERE NOT s.is_active AND d.status='pending' AND d.next_attempt_at <= $1 FOR UPDATE OF d SKIP LOCKED)
        UPDATE webhook_deliveries d SET status='failed',last_error='subscription inactive; delivery stopped',updated_at=now()
        FROM inactive WHERE d.id=inactive.id")
        .bind(now).execute(&mut *tx).await?;
    let rows = sqlx::query("WITH due AS (
        SELECT d.id,d.subscription_id,d.event_id,d.attempt_count,d.next_attempt_at,e.body,s.url,s.secret_ciphertext,
               CASE WHEN s.previous_secret_expires_at > $1 THEN s.previous_secret_ciphertext END AS previous
        FROM webhook_deliveries d JOIN webhook_events e ON e.id=d.event_id
        JOIN webhook_subscriptions s ON s.id=d.subscription_id
        WHERE s.is_active AND d.status='pending' AND d.next_attempt_at <= $1
        ORDER BY d.next_attempt_at LIMIT $3 FOR UPDATE OF d SKIP LOCKED),
        leased AS (UPDATE webhook_deliveries d SET next_attempt_at=$2,updated_at=now()
        FROM due WHERE due.id=d.id RETURNING d.id)
        SELECT due.* FROM due JOIN leased USING(id) ORDER BY due.next_attempt_at")
        .bind(now).bind(until).bind(limit).fetch_all(&mut *tx).await?;
    let deliveries = rows
        .into_iter()
        .map(|r| {
            Ok(Delivery {
                id: r.try_get("id")?,
                subscription: r.try_get("subscription_id")?,
                event: r.try_get("event_id")?,
                body: r.try_get("body")?,
                url: r.try_get("url")?,
                attempts: r.try_get("attempt_count")?,
                current: r.try_get("secret_ciphertext")?,
                previous: r.try_get("previous")?,
            })
        })
        .collect::<sqlx::Result<_>>()?;
    tx.commit().await?;
    Ok(deliveries)
}

pub(super) async fn record(
    pool: &PgPool,
    delivery: &Delivery,
    at: DateTime<Utc>,
    result: Attempt,
) -> sqlx::Result<()> {
    let (status, next) = if result.code.is_some_and(|v| (200..300).contains(&v)) {
        ("succeeded", None)
    } else if let Some(delay) =
        retry_delay(delivery.attempts, rand::thread_rng().gen_range(-1.0..=1.0))
    {
        ("pending", Some(Utc::now() + delay))
    } else {
        ("failed", None)
    };
    sqlx::query("WITH updated AS (
        UPDATE webhook_deliveries SET status=$2, attempt_count=attempt_count+1,
            last_status_code=$3,last_error=$4,next_attempt_at=coalesce($5,next_attempt_at),updated_at=now()
        WHERE id=$1 RETURNING id)
        INSERT INTO webhook_delivery_attempts(id,delivery_id,attempted_at,status_code,error,duration_ms,response_excerpt)
        SELECT $6,id,$7,$3,$4,$8,$9 FROM updated")
        .bind(delivery.id).bind(status).bind(result.code).bind(result.error).bind(next)
        .bind(Uuid::new_v4()).bind(at).bind(result.duration_ms).bind(result.excerpt).execute(pool).await?;
    Ok(())
}

fn retry_delay(prior: i32, jitter: f64) -> Option<chrono::Duration> {
    let seconds = [5, 300, 1800, 7200, 18000, 36000, 36000].get(usize::try_from(prior).ok()?)?;
    let micros = (*seconds as f64 * 1e6 * (1.0 + 0.1 * jitter)).round() as i64;
    Some(chrono::Duration::microseconds(micros))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_budget_uses_seven_delays_before_terminal_failure() {
        assert_eq!(retry_delay(0, -1.0).unwrap().num_milliseconds(), 4500);
        assert_eq!(retry_delay(1, 0.0).unwrap().num_minutes(), 5);
        assert_eq!(retry_delay(6, 1.0).unwrap().num_hours(), 11);
        assert!(retry_delay(7, 0.0).is_none());
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    async fn fixture() -> PgPool {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE webhook_subscriptions(id uuid, is_active bool, url text, secret_ciphertext bytea, previous_secret_ciphertext bytea, previous_secret_expires_at timestamptz);
            CREATE TEMP TABLE webhook_events(id uuid, body text);
            CREATE TEMP TABLE webhook_deliveries(id uuid,subscription_id uuid,event_id uuid,status text,attempt_count int,next_attempt_at timestamptz,updated_at timestamptz,last_error text,last_status_code int);
            CREATE TEMP TABLE webhook_delivery_attempts(id uuid,delivery_id uuid,attempted_at timestamptz,status_code int,error text,duration_ms int CHECK(duration_ms>=0),response_excerpt text);
            INSERT INTO webhook_events VALUES(gen_random_uuid(),'{}');
            INSERT INTO webhook_subscriptions SELECT gen_random_uuid(),v,'https://example.test','key','old',now()+interval '1 minute' FROM unnest(array[true,false]) v;
            INSERT INTO webhook_deliveries SELECT gen_random_uuid(),s.id,e.id,'pending',0,now(),now(),null,null FROM webhook_subscriptions s CROSS JOIN webhook_events e;")
            .execute(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn expired_lease_can_be_reclaimed_and_attempt_history_is_atomic() {
        let pool = fixture().await;
        let now = Utc::now();
        let until = now + chrono::Duration::seconds(40);
        let initial = claim(&pool, now, until, 5).await.unwrap();
        assert_eq!(initial.len(), 1);
        assert!(initial[0].previous.is_some());
        assert!(claim(&pool, now, until, 5).await.unwrap().is_empty());
        let later = now + chrono::Duration::seconds(65);
        let recovered = claim(&pool, later, later + chrono::Duration::minutes(1), 5)
            .await
            .unwrap();
        assert_eq!(recovered[0].id, initial[0].id);
        assert!(recovered[0].previous.is_none());
        let inactive = sqlx::query_scalar::<_, i32>(
            "SELECT attempt_count FROM webhook_deliveries WHERE status='failed'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(inactive, 0);
        let result = |duration_ms| Attempt {
            duration_ms,
            code: Some(204),
            error: None,
            excerpt: Some(String::new()),
        };
        let d = &recovered[0];
        assert!(record(&pool, d, later, result(-1)).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT status FROM webhook_deliveries WHERE id=$1")
                .bind(d.id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            "pending"
        );
        record(&pool, d, later, result(3)).await.unwrap();
        sqlx::query("DELETE FROM webhook_deliveries WHERE id=$1")
            .bind(d.id)
            .execute(&pool)
            .await
            .unwrap();
        record(&pool, d, later, result(2)).await.unwrap();
        let durations =
            sqlx::query_scalar::<_, i32>("SELECT duration_ms FROM webhook_delivery_attempts")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(durations, [3]);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn throttled_delivery_is_available_to_the_next_owner_only_when_due() {
        let pool = fixture().await;
        let start = Utc::now();
        let lease = chrono::Duration::seconds(40);
        let first = claim(&pool, start, start + lease, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let throttled = Attempt {
            code: Some(429),
            error: Some("HTTP 429".into()),
            duration_ms: 1,
            excerpt: Some("busy".into()),
        };
        record(&pool, &first, start, throttled).await.unwrap();
        let due: DateTime<Utc> =
            sqlx::query_scalar("SELECT next_attempt_at FROM webhook_deliveries WHERE id=$1")
                .bind(first.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let just_before = due - chrono::Duration::microseconds(1);
        assert!(
            claim(&pool, just_before, just_before + lease, 1)
                .await
                .unwrap()
                .is_empty()
        );
        let second = claim(&pool, due, due + lease, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            (second.id, second.event, second.body, second.attempts),
            (first.id, first.event, first.body, 1)
        );
    }
}
