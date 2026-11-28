//! Receive authenticated Google Play updates through Cloud Pub/Sub.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Deserialize)]
struct Envelope {
    message: Message,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    message_id: String,
    data: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Data {
    package_name: String,
    subscription_notification: Option<Change>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Change {
    notification_type: i32,
    purchase_token: String,
    subscription_id: Option<String>,
}

fn message(bytes: &[u8], package: &str) -> Result<(String, Option<Change>), Failure> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Failure::Invalid)?;
    let id = envelope.message.message_id;
    let data = STANDARD
        .decode(envelope.message.data)
        .map_err(|_| Failure::Invalid)?;
    let data: Data = serde_json::from_slice(&data).map_err(|_| Failure::Invalid)?;
    if id.is_empty() || id.chars().nth(128).is_some() || data.package_name != package {
        return Err(Failure::Invalid);
    }
    if data
        .subscription_notification
        .as_ref()
        .is_some_and(|c| c.purchase_token.is_empty() || c.purchase_token.chars().nth(512).is_some())
    {
        return Err(Failure::Invalid);
    }
    Ok((id, data.subscription_notification))
}

pub(in crate::profile) async fn handle(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    if method != Method::POST {
        return passkeys::post_required();
    }
    let Some(provider) = state.google_play.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"billing not enabled"})),
        )
            .into_response();
    };
    match receive(&state, provider, &headers, &bytes).await {
        Ok(handled) => Json(json!({"received":true,"handled":handled})).into_response(),
        Err(Failure::Invalid | Failure::Gone) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid push token"})),
        )
            .into_response(),
        Err(Failure::Unavailable) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn receive(
    state: &Profile,
    provider: &Provider,
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<bool, Failure> {
    let identity = provider.push.as_ref().ok_or(Failure::Unavailable)?;
    let bearer = crate::csrf::bearer(headers).ok_or(Failure::Invalid)?;
    let client = provider.client().await?;
    identity.verify(bearer, &client.http).await?;
    let (id, change) = message(bytes, &provider.package)?;
    let _slot = provider
        .store_slots
        .try_acquire()
        .map_err(|_| Failure::Unavailable)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO google_notifications(message_id,status) VALUES($1,'deferred') ON CONFLICT DO NOTHING")
        .bind(&id).execute(&mut *tx).await?;
    let status: String = sqlx::query_scalar(
        "SELECT status FROM google_notifications WHERE message_id=$1 FOR UPDATE",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?;
    if status == "processed" {
        return Ok(false);
    }
    let outcome = match change {
        Some(c) if matches!(c.notification_type, 1..=7 | 10 | 12 | 13) => {
            reconcile(&mut tx, provider, &c, state.registration.hooks).await?
        }
        _ => Outcome::Ignored,
    };
    let (status, reason) = match &outcome {
        Outcome::Deferred(reason) => ("deferred", Some(*reason)),
        _ => ("processed", None),
    };
    sqlx::query("UPDATE google_notifications SET status=$2,reason=$3,processed_at=now() WHERE message_id=$1")
        .bind(&id).bind(status).bind(reason).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(matches!(outcome, Outcome::Applied))
}

impl From<sqlx::Error> for Failure {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}
enum Outcome {
    Applied,
    Ignored,
    Deferred(&'static str),
}
type Tx<'a> = Transaction<'a, Postgres>;

async fn missing_owner(tx: &mut Tx<'_>, change: &Change) -> sqlx::Result<Outcome> {
    if matches!(change.notification_type, 3 | 12 | 13) {
        let has_entitlement = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT FROM entitlements WHERE source='google' AND external_ref=$1)",
        )
        .bind(&change.purchase_token)
        .fetch_one(&mut **tx)
        .await?;
        if !has_entitlement {
            return Ok(Outcome::Deferred("no entitlement for purchase"));
        }
    }
    Ok(Outcome::Deferred("unmapped purchase"))
}

async fn reconcile(
    tx: &mut Tx<'_>,
    provider: &Provider,
    change: &Change,
    hooks: bool,
) -> Result<Outcome, Failure> {
    let token = &change.purchase_token;
    lock_purchase(tx, token).await?;
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM google_purchases WHERE purchase_token=$1")
            .bind(token)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(user) = owner else {
        return Ok(missing_owner(tx, change).await?);
    };
    let client = provider.client().await?;
    let subscription = match client.subscription(&provider.package, token, true).await {
        Ok(sub) => sub,
        Err(Failure::Gone) if matches!(change.notification_type, 12 | 13) => {
            return revoke(tx, user, token, hooks).await;
        }
        Err(Failure::Gone) => return Ok(Outcome::Deferred("purchase unavailable")),
        Err(err) => return Err(err),
    };
    match subscription.subscription_state.as_str() {
        "SUBSCRIPTION_STATE_EXPIRED"
        | "SUBSCRIPTION_STATE_ON_HOLD"
        | "SUBSCRIPTION_STATE_PAUSED" => revoke(tx, user, token, hooks).await,
        "SUBSCRIPTION_STATE_ACTIVE"
        | "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"
        | "SUBSCRIPTION_STATE_CANCELED" => grant(tx, user, change, &subscription, hooks).await,
        _ => Ok(Outcome::Deferred("subscription state unavailable")),
    }
}

async fn grant(
    tx: &mut Tx<'_>,
    user: Uuid,
    change: &Change,
    sub: &provider::Subscription,
    hooks: bool,
) -> Result<Outcome, Failure> {
    let now = Utc::now();
    let products = sub.active_products(now);
    if products.is_empty()
        && sub.subscription_state == "SUBSCRIPTION_STATE_CANCELED"
        && sub.expired_items(now)
    {
        return revoke(tx, user, &change.purchase_token, hooks).await;
    }
    let selected = change
        .subscription_id
        .as_deref()
        .filter(|s| products.contains(s))
        .or_else(|| {
            (products.len() == 1)
                .then(|| products.first().copied())
                .flatten()
        });
    let Some(selected) = selected else {
        return Ok(Outcome::Deferred("unresolved subscription product"));
    };
    let mapping: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT product_key,plan FROM google_products WHERE google_product_id=$1")
            .bind(selected)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((product, plan)) = mapping else {
        return Ok(Outcome::Deferred("unknown product"));
    };
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
    if !store_products::grantable(tx, &product).await? {
        return Ok(Outcome::Deferred("inactive product"));
    }
    let grant = billing_grants::Grant {
        source: "google",
        reference: Some(&change.purchase_token),
        product: &product,
        plan: plan.as_deref(),
        expires: Some(sub.expiry(selected, now)?),
    };
    if !billing_grants::apply(tx, user, grant, hooks).await? {
        return Err(Failure::Unavailable);
    }
    Ok(Outcome::Applied)
}

async fn revoke(tx: &mut Tx<'_>, user: Uuid, token: &str, hooks: bool) -> Result<Outcome, Failure> {
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM entitlements WHERE user_id=$1 AND source='google' AND external_ref=$2)")
        .bind(user).bind(token).fetch_one(&mut **tx).await?;
    if !exists {
        return Ok(Outcome::Deferred("no entitlement for purchase"));
    }
    if !billing_grants::revoke(tx, token, Some(user), Some("google"), None, hooks).await? {
        return Err(Failure::Unavailable);
    }
    Ok(Outcome::Applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn records_the_missing_dependency_for_an_unowned_purchase() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE entitlements(source text,external_ref text)")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO entitlements VALUES('stripe','empty'),('google','orphan')")
            .execute(&mut *tx)
            .await
            .unwrap();
        for (kind, token, reason) in [
            (2, "empty", "unmapped purchase"),
            (3, "empty", "no entitlement for purchase"),
            (12, "empty", "no entitlement for purchase"),
            (13, "empty", "no entitlement for purchase"),
            (13, "orphan", "unmapped purchase"),
        ] {
            let change = Change {
                notification_type: kind,
                purchase_token: token.into(),
                subscription_id: None,
            };
            assert!(
                matches!(missing_owner(&mut tx,&change).await.unwrap(), Outcome::Deferred(actual) if actual == reason)
            );
        }
    }

    #[test]
    fn counts_notification_identifiers_in_unicode_characters() {
        for (id_length, token_length, accepted) in [
            (128, 1, true),
            (1, 512, true),
            (128, 512, true),
            (129, 1, false),
            (1, 513, false),
            (0, 1, false),
            (1, 0, false),
        ] {
            let id = "é".repeat(id_length);
            let token = "🐢".repeat(token_length);
            let payload = json!({"packageName":"org.example","subscriptionNotification":{
                "notificationType":2,"purchaseToken":token
            }});
            let bytes = serde_json::to_vec(&json!({"message":{
                "messageId":id,"data":STANDARD.encode(payload.to_string())
            }}))
            .unwrap();
            let result = message(&bytes, "org.example");
            assert_eq!(result.is_ok(), accepted, "{id_length}, {token_length}");
            if let Ok((decoded_id, change)) = result {
                assert_eq!(decoded_id, id);
                assert_eq!(change.unwrap().purchase_token, token);
            }
        }
    }

    #[test]
    fn parses_package_scoped_push_without_a_legacy_product_id() {
        let data = json!({"packageName":"org.example","subscriptionNotification":{"notificationType":2,"purchaseToken":"test-purchase"}});
        let bytes = serde_json::to_vec(
            &json!({"message":{"messageId":"42","data":STANDARD.encode(data.to_string())}}),
        )
        .unwrap();
        let (id, change) = message(&bytes, "org.example").unwrap();
        assert_eq!(id, "42");
        assert_eq!(change.unwrap().purchase_token, "test-purchase");
        assert!(message(&bytes, "another.package").is_err());
    }
}
