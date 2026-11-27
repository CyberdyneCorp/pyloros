use super::*;
type Tx<'a> = Transaction<'a, Postgres>;

enum Outcome {
    Applied,
    Ignored,
    Deferred(String),
    NeedsDispatcher,
}
pub(super) async fn process(
    pool: &PgPool,
    event: &Event,
    hooks: bool,
) -> sqlx::Result<Option<bool>> {
    let mut tx = pool.begin().await?;
    // The event row also serializes first delivery against competing retries.
    sqlx::query(
        "INSERT INTO stripe_events(event_id,status,processed_at) VALUES($1,'deferred',now())
        ON CONFLICT(event_id) DO NOTHING",
    )
    .bind(&event.id)
    .execute(&mut *tx)
    .await?;
    let status: String =
        sqlx::query_scalar("SELECT status FROM stripe_events WHERE event_id=$1 FOR UPDATE")
            .bind(&event.id)
            .fetch_one(&mut *tx)
            .await?;
    if status == "processed" {
        return Ok(Some(false));
    }
    if let Some(reference) = event.reference() {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('stripe-reference'),hashtext($1))")
            .bind(reference)
            .execute(&mut *tx)
            .await?;
    }
    let outcome = match event.kind.as_str() {
        "checkout.session.completed"
        | "customer.subscription.created"
        | "customer.subscription.updated" => grant(&mut tx, event, hooks).await?,
        "charge.refunded"
            if event.data.object.get("refunded").and_then(Value::as_bool) != Some(true) =>
        {
            Outcome::Applied
        }
        "charge.refunded" | "charge.dispute.funds_withdrawn" | "customer.subscription.deleted" => {
            revoke(&mut tx, event, hooks).await?
        }
        _ => Outcome::Ignored,
    };
    let (status, reason, handled) = match outcome {
        Outcome::Applied => ("processed", None, true),
        Outcome::Ignored => ("processed", None, false),
        Outcome::Deferred(reason) => ("deferred", Some(reason), false),
        Outcome::NeedsDispatcher => return Ok(None),
    };
    sqlx::query(
        "UPDATE stripe_events SET status=$2,reason=$3,processed_at=now() WHERE event_id=$1",
    )
    .bind(&event.id)
    .bind(status)
    .bind(reason.as_deref())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if let Some(reason) = reason {
        eprintln!(
            "{}",
            json!({"event":"billing_event_deferred","provider":"stripe","event_id":event.id,"event_type":event.kind,"reason":reason})
        );
    }
    Ok(Some(handled))
}

async fn customer(tx: &mut Tx<'_>, event: &Event) -> sqlx::Result<Result<Uuid, String>> {
    let customer = event.text("customer").filter(|s| !s.is_empty());
    let mapped = if let Some(id) = customer {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('stripe-customer'),hashtext($1))")
            .bind(id)
            .execute(&mut **tx)
            .await?;
        sqlx::query_scalar::<_, Uuid>(
            "SELECT user_id FROM stripe_customers WHERE stripe_customer_id=$1",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
    } else {
        None
    };
    let user = match event.text("client_reference_id").filter(|v| !v.is_empty()) {
        Some(reference) => Uuid::parse_str(reference).ok(),
        None => mapped,
    };
    let Some(user) = user else {
        return Ok(Err("unmapped customer".into()));
    };
    if mapped.is_some_and(|id| id != user) {
        return Ok(Err("customer belongs to another user".into()));
    }
    let found = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_optional(&mut **tx)
        .await?;
    if found.is_none() {
        return Ok(Err(user.to_string()));
    }
    if mapped.is_none()
        && let Some(id) = customer
    {
        sqlx::query("INSERT INTO stripe_customers(id,user_id,stripe_customer_id) VALUES($1,$2,$3)")
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(Ok(user))
}

async fn grant(tx: &mut Tx<'_>, event: &Event, hooks: bool) -> sqlx::Result<Outcome> {
    let Some((product, plan)) = event.product() else {
        return Ok(Outcome::Deferred("no product metadata".into()));
    };
    let user = match customer(tx, event).await? {
        Ok(user) => user,
        Err(reason) => return Ok(Outcome::Deferred(reason)),
    };
    if !store_products::grantable(tx, product).await? {
        return Ok(Outcome::Deferred(product.into()));
    }
    let applied = billing_grants::apply(
        tx,
        user,
        billing_grants::Grant {
            product,
            plan,
            expires: event.expires()?,
            reference: event.reference(),
            source: "stripe",
        },
        hooks,
    )
    .await?;
    Ok(if applied {
        Outcome::Applied
    } else {
        Outcome::NeedsDispatcher
    })
}

async fn revoke(tx: &mut Tx<'_>, event: &Event, hooks: bool) -> sqlx::Result<Outcome> {
    let Some(reference) = event.reference().filter(|s| !s.is_empty()) else {
        return Ok(Outcome::Deferred("no matchable reference".into()));
    };
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM entitlements WHERE external_ref=$1)")
            .bind(reference)
            .fetch_one(&mut **tx)
            .await?;
    if !exists {
        return Ok(Outcome::Deferred("no entitlement for reference".into()));
    }
    if !billing_grants::revoke(tx, reference, None, None, None, hooks).await? {
        return Ok(Outcome::NeedsDispatcher);
    }
    Ok(Outcome::Applied)
}
