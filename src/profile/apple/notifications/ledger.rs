use super::*;

enum Outcome {
    Applied,
    Ignored,
    Deferred(&'static str),
    NeedsDispatcher,
}
type Tx<'a> = Transaction<'a, Postgres>;

pub(super) async fn process(
    pool: &PgPool,
    delivery: Delivery,
    hooks: bool,
) -> sqlx::Result<Option<bool>> {
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO apple_notifications(notification_uuid,status) VALUES($1,'deferred') ON CONFLICT DO NOTHING")
        .bind(&delivery.id).execute(&mut *tx).await?;
    let status: String = sqlx::query_scalar(
        "SELECT status FROM apple_notifications WHERE notification_uuid=$1 FOR UPDATE",
    )
    .bind(&delivery.id)
    .fetch_one(&mut *tx)
    .await?;
    if status == "processed" {
        return Ok(Some(false));
    }
    let outcome = apply(&mut tx, &delivery.effect, hooks).await?;
    let (status, reason, handled) = match outcome {
        Outcome::Applied => ("processed", None, true),
        Outcome::Ignored => ("processed", None, false),
        Outcome::Deferred(reason) => ("deferred", Some(reason), false),
        Outcome::NeedsDispatcher => return Ok(None),
    };
    sqlx::query("UPDATE apple_notifications SET status=$2,reason=$3,processed_at=now() WHERE notification_uuid=$1")
        .bind(&delivery.id).bind(status).bind(reason).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Some(handled))
}

async fn apply(tx: &mut Tx<'_>, effect: &Effect, hooks: bool) -> sqlx::Result<Outcome> {
    let purchase = match effect {
        Effect::Ignore => return Ok(Outcome::Ignored),
        Effect::Grant(p, _) | Effect::Revoke(p) => p,
    };
    let reference = &purchase.original_transaction_id;
    lock_purchase(tx, reference).await?;
    let user: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM apple_transactions WHERE original_transaction_id=$1",
    )
    .bind(reference)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(user) = user else {
        return Ok(Outcome::Deferred("unmapped transaction"));
    };
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
    match effect {
        Effect::Grant(_, expiry) => grant(tx, user, purchase, *expiry, hooks).await,
        Effect::Revoke(_) => revoke(tx, user, reference, hooks).await,
        Effect::Ignore => Ok(Outcome::Ignored),
    }
}
async fn grant(
    tx: &mut Tx<'_>,
    user: Uuid,
    p: &Purchase,
    expiry: Option<DateTime<Utc>>,
    hooks: bool,
) -> sqlx::Result<Outcome> {
    let Some((product, plan)) = mapping(tx, &p.product_id).await? else {
        return Ok(Outcome::Deferred("unknown product"));
    };
    if !store_products::grantable(tx, &product).await? {
        return Ok(Outcome::Deferred("inactive product"));
    }
    if stale_purchase(
        tx,
        user,
        &p.original_transaction_id,
        &product,
        plan.as_deref(),
        expiry,
        p.signed_date,
    )
    .await?
    {
        return Ok(Outcome::Ignored);
    }
    let grant = billing_grants::Grant {
        product: &product,
        plan: plan.as_deref(),
        expires: expiry,
        reference: Some(&p.original_transaction_id),
        source: "apple",
    };
    Ok(if billing_grants::apply(tx, user, grant, hooks).await? {
        Outcome::Applied
    } else {
        Outcome::NeedsDispatcher
    })
}
async fn revoke(
    tx: &mut Tx<'_>,
    user: Uuid,
    reference: &str,
    hooks: bool,
) -> sqlx::Result<Outcome> {
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM entitlements WHERE user_id=$1 AND source='apple' AND external_ref=$2)").bind(user).bind(reference).fetch_one(&mut **tx).await?;
    if !exists {
        return Ok(Outcome::Deferred("no entitlement for transaction"));
    }
    if !billing_grants::revoke(tx, reference, Some(user), Some("apple"), None, hooks).await? {
        return Ok(Outcome::NeedsDispatcher);
    }
    Ok(Outcome::Applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn deferred_refund_can_be_retried_after_an_owner_is_bound() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE apple_notifications(notification_uuid text PRIMARY KEY,status text,reason text,processed_at timestamptz);
            CREATE TEMP TABLE apple_transactions(original_transaction_id text,user_id uuid);
            CREATE TEMP TABLE users(id uuid);
            CREATE TEMP TABLE entitlements(id uuid DEFAULT gen_random_uuid(), product_key text DEFAULT 'fixture',plan text,user_id uuid,source text,external_ref text,status text,revoked_at timestamptz,updated_at timestamptz);")
            .execute(&pool).await.unwrap();
        let user = Uuid::new_v4();
        let refund = || Delivery {
            id: "same-delivery".into(),
            effect: Effect::Revoke(Purchase {
                bundle_id: "test".into(),
                environment: "Sandbox".into(),
                transaction_id: "t".into(),
                original_transaction_id: "p".into(),
                product_id: "s".into(),
                signed_date: 0,
                expires_date: None,
                revocation_date: Some(1),
                product_type: "Non-Consumable".into(),
            }),
        };
        assert_eq!(process(&pool, refund(), false).await.unwrap(), Some(false));
        sqlx::query("INSERT INTO users VALUES($1)")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO apple_transactions VALUES('p',$1)")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO entitlements(user_id,source,external_ref,status,revoked_at,updated_at) VALUES($1,'apple','p','active',NULL,now()),($1,'stripe','p','active',NULL,now())").bind(user).execute(&pool).await.unwrap();
        assert_eq!(process(&pool, refund(), false).await.unwrap(), Some(true));
        assert_eq!(process(&pool, refund(), false).await.unwrap(), Some(false));
        let active: Vec<String> =
            sqlx::query_scalar("SELECT source FROM entitlements WHERE status='active'")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(active, ["stripe"]);
    }
}
