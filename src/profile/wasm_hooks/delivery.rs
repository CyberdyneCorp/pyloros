//! Persist the exact component version and permitted event fields at commit.
use super::*;

pub(super) mod worker;

#[derive(Clone, Copy)]
pub(in crate::profile) enum Producer {
    Store,
    Administrator,
    Role,
    Registration,
    Login,
}

impl Producer {
    fn enabled(self) -> Result<bool, Box<dyn Error>> {
        let name = match self {
            Self::Store => "PYLOROS_STORE_HOOK_DISPATCH",
            Self::Login => "PYLOROS_LOGIN_HOOK_DISPATCH",
            Self::Registration => "PYLOROS_REGISTRATION_HOOK_DISPATCH",
            Self::Role => "PYLOROS_ROLE_HOOK_DISPATCH",
            Self::Administrator => "PYLOROS_ADMIN_ENTITLEMENT_HOOK_DISPATCH",
        };
        config::flag_with_default(name, false)
    }
}

pub(in crate::profile) struct Entitlement<'a> {
    pub id: Uuid,
    pub user: Option<Uuid>,
    pub product: &'a str,
    pub plan: Option<&'a str>,
}

impl Entitlement<'_> {
    pub(in crate::profile) async fn granted(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        producer: Producer,
        org: Option<Uuid>,
        source: &str,
    ) -> sqlx::Result<bool> {
        let payload = json!({"entitlement_id":self.id, "product_key":self.product, "plan":self.plan,
            "organization_id":org,"source":source});
        enqueue(tx, producer, "entitlement_granted", self.user, payload).await
    }

    pub(in crate::profile) async fn revoked(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        producer: Producer,
    ) -> sqlx::Result<bool> {
        let payload = json!({"entitlement_id":self.id,"product_key":self.product,"plan":self.plan});
        enqueue(tx, producer, "entitlement_revoked", self.user, payload).await
    }
}

pub(in crate::profile) async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    producer: Producer,
    event: &str,
    user: Option<Uuid>,
    payload: Value,
) -> sqlx::Result<bool> {
    enqueue_with_private_fields(tx, producer, event, user, payload, json!({})).await
}

pub(in crate::profile) async fn registered(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    email: &str,
    address: &str,
) -> sqlx::Result<bool> {
    enqueue_with_private_fields(
        tx,
        Producer::Registration,
        "user_registered",
        Some(user),
        json!({}),
        json!({"email":email, "address":address}),
    )
    .await
}

pub(crate) async fn logged_in(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    email: Option<&str>,
    origin: crate::grant_response::SessionOrigin<'_>,
) -> sqlx::Result<bool> {
    enqueue_with_private_fields(
        tx,
        Producer::Login,
        "user_logged_in",
        Some(user),
        json!({}),
        json!({"email":email, "ip":origin.ip, "user_agent":origin.user_agent}),
    )
    .await
}

async fn enqueue_with_private_fields(
    tx: &mut Transaction<'_, Postgres>,
    producer: Producer,
    event: &str,
    user: Option<Uuid>,
    payload: Value,
    private: Value,
) -> sqlx::Result<bool> {
    if !registration::pending_hook(tx, event).await? {
        return Ok(true);
    }
    if !producer
        .enabled()
        .map_err(|e| sqlx::Error::Configuration(e.to_string().into()))?
    {
        return Ok(false);
    }
    stage(tx, event, user, payload, private).await
}

async fn stage(
    tx: &mut Transaction<'_, Postgres>,
    event: &str,
    user: Option<Uuid>,
    mut payload: Value,
    private: Value,
) -> sqlx::Result<bool> {
    payload["user_id"] = json!(user);
    payload["event_type"] = json!(event);
    // A single snapshot checks the entire recipient set and pins every selected digest.
    sqlx::query_scalar(
        "WITH recipients AS MATERIALIZED (
          SELECT h.id,h.name,h.timeout_seconds,h.receive_pii,b.sha256 FROM hooks h
          LEFT JOIN pyloros_hook_bindings b ON b.hook_id=h.id WHERE h.is_active AND h.event_type=$1
         ), ready AS (SELECT NOT EXISTS(SELECT FROM recipients WHERE sha256 IS NULL) AS ok),
         queued AS (
          INSERT INTO pyloros_hook_deliveries(id,hook_id,sha256,hook_name,event_type,user_id,payload,timeout_seconds)
          SELECT gen_random_uuid(),id,sha256,name,$1,$2,CASE WHEN receive_pii THEN $3::jsonb || $4::jsonb ELSE $3::jsonb END,least(30,greatest(1,timeout_seconds))
          FROM recipients,ready WHERE ok
         ) SELECT ok FROM ready")
        .bind(event).bind(user).bind(payload).bind(private).fetch_one(&mut **tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_partial_binding_set_cannot_queue_partial_delivery() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid PRIMARY KEY);
            CREATE TEMP TABLE hooks(id uuid PRIMARY KEY, name text,timeout_seconds int,event_type text,is_active boolean, receive_pii boolean DEFAULT false);
            CREATE TEMP TABLE pyloros_hook_artifacts(sha256 text PRIMARY KEY);")
            .execute(&mut *tx).await.unwrap();
        for ddl in [
            include_str!("../../../migrations/002_hook_bindings.sql"),
            include_str!("../../../migrations/003_hook_deliveries.sql"),
        ] {
            sqlx::raw_sql(&ddl.replace("CREATE TABLE", "CREATE TEMP TABLE"))
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        let evt = "entitlement_granted";
        for _ in 0..2 {
            sqlx::query("INSERT INTO hooks VALUES(gen_random_uuid(),'test',3,$1,true)")
                .bind(evt)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO pyloros_hook_artifacts VALUES ('v1'),('v2')")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO pyloros_hook_bindings SELECT id,'v1' FROM hooks LIMIT 1")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(
            !stage(&mut tx, evt, None, json!({}), json!({}))
                .await
                .unwrap()
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pyloros_hook_deliveries")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        sqlx::query(
            "INSERT INTO pyloros_hook_bindings SELECT id,'v2' FROM hooks ON CONFLICT DO NOTHING",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("UPDATE hooks SET receive_pii=true WHERE id=(SELECT hook_id FROM pyloros_hook_bindings WHERE sha256='v2')")
            .execute(&mut *tx).await.unwrap();
        assert!(
            stage(
                &mut tx,
                evt,
                None,
                json!({"plan":"pro"}),
                json!({"email":"test@example.com"})
            )
            .await
            .unwrap()
        );
        sqlx::query("UPDATE pyloros_hook_bindings SET sha256='v2'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT sha256 FROM pyloros_hook_deliveries
            WHERE timeout_seconds=3 AND payload->>'plan'='pro' ORDER BY sha256",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert_eq!(rows, ["v1", "v2"]);
        let recipients: Vec<String> = sqlx::query_scalar(
            "SELECT sha256 FROM pyloros_hook_deliveries WHERE payload ? 'email'",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert_eq!(recipients, ["v2"]);
    }
}
