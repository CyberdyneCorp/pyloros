//! Signed Stripe notifications and transactional fulfillment.
use super::*;
use axum::body::Bytes;
use ring::hmac;
use serde_json::Value;
mod ledger;
mod period;

pub(super) struct Verifier(hmac::Key);
impl Verifier {
    pub(super) fn configured() -> Result<Option<Self>, Box<dyn Error>> {
        if !config::flag("BILLING_ENABLED")? {
            return Ok(None);
        }
        Ok(env::var("STRIPE_WEBHOOK_SECRET")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|s| Self(hmac::Key::new(hmac::HMAC_SHA256, s.as_bytes()))))
    }

    fn accepts(&self, header: &str, payload: &[u8], now: i64) -> bool {
        let mut fields = header.split(',').filter_map(|p| p.split_once('='));
        let Some(timestamp) = fields
            .clone()
            .find_map(|(k, v)| (k == "t").then_some(v))
            .and_then(|v| v.parse::<i64>().ok())
        else {
            return false;
        };
        if timestamp < now.saturating_sub(300) {
            return false;
        }
        let mut signer = hmac::Context::with_key(&self.0);
        signer.update(timestamp.to_string().as_bytes());
        signer.update(b".");
        signer.update(payload);
        let expected = data_encoding::HEXLOWER.encode(signer.sign().as_ref());
        use subtle::ConstantTimeEq;
        fields.any(|(k, v)| k == "v1" && bool::from(v.as_bytes().ct_eq(expected.as_bytes())))
    }
}

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        return passkeys::post_required();
    }
    let Some(verifier) = &state.stripe_events else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"billing not enabled"})),
        )
            .into_response();
    };
    let signature = headers
        .get("stripe-signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !verifier.accepts(signature, &body, Utc::now().timestamp()) {
        return invalid();
    }
    let Some(event) = Event::parse(&body) else {
        return invalid();
    };
    match ledger::process(&state.pool, &event, state.registration.hooks).await {
        Ok(Some(handled)) => Json(json!({"received":true,"handled":handled})).into_response(),
        Ok(None) => crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Entitlement hook dispatcher unavailable",
        ),
        Err(_) => internal(),
    }
}
fn invalid() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":"invalid signature"})),
    )
        .into_response()
}

#[derive(Deserialize)]
struct Event {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    data: EventData,
}
#[derive(Deserialize)]
struct EventData {
    object: period::BillingObject,
}

impl Event {
    fn parse(body: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(body).ok()?;
        crate::stored_json::check_integers(text).ok()?;
        serde_json::from_str(text).ok()
    }

    fn text(&self, k: &str) -> Option<&str> {
        self.data.object.fields.get(k)?.as_str()
    }
    fn reference(&self) -> Option<&str> {
        let field = if self.kind.starts_with("customer.subscription.") {
            "id"
        } else {
            "subscription"
        };
        self.text(field)
            .filter(|s| !s.is_empty())
            .or_else(|| self.text("payment_intent"))
    }
    fn product(&self) -> Option<(&str, Option<&str>)> {
        let object = &self.data.object;
        let price = object
            .item
            .as_ref()
            .and_then(|item| item.price.get("metadata"));
        [price, object.fields.get("metadata")]
            .into_iter()
            .flatten()
            .find_map(|meta| {
                let product = meta
                    .get("cyberdyne_product")?
                    .as_str()
                    .filter(|s| !s.is_empty())?;
                Some((product, meta.get("cyberdyne_plan").and_then(Value::as_str)))
            })
    }
    fn expires(&self) -> sqlx::Result<Option<DateTime<Utc>>> {
        let object = &self.data.object;
        period::expiry(object.current_period_end.as_deref(), object.item.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkout_and_cancellation_choose_their_billing_reference() {
        for (kind, subscription, expected) in [
            ("checkout.session.completed", "sub_primary", "sub_primary"),
            ("checkout.session.completed", "", "pi_purchase"),
            ("customer.subscription.deleted", "sub_other", "sub_object"),
        ] {
            let event: Event = serde_json::from_value(json!({
                "id": "evt_purchase",
                "type": kind,
                "data": {"object": {
                    "id": "sub_object",
                    "subscription": subscription,
                    "payment_intent": "pi_purchase"
                }}
            }))
            .unwrap();
            assert_eq!(event.reference(), Some(expected));
        }
    }

    #[test]
    fn signature_checks_original_bytes_and_expires_after_five_minutes() {
        let verifier = Verifier(hmac::Key::new(hmac::HMAC_SHA256, b"test-only"));
        let payload = br#"{"id":"evt_test"}"#;
        let signature = data_encoding::HEXLOWER
            .encode(hmac::sign(&verifier.0, &[b"1000.".as_slice(), payload].concat()).as_ref());
        let header = format!("t=1000,v1=unused,v1={signature}");
        assert!(verifier.accepts(&header, payload, 1300));
        assert!(!verifier.accepts(&header, payload, 1301));
        assert!(!verifier.accepts(&header, b"{}", 1000));
        assert!(!verifier.accepts("", payload, 1000));
    }

    #[test]
    fn subscription_metadata_and_period_end_have_independent_precedence() {
        for (top, first, item_metadata, product, plan, expiry) in [
            (
                json!(0),
                json!(123),
                json!({"cyberdyne_product":"item"}),
                "item",
                None,
                Some(0),
            ),
            (
                json!("456"),
                json!(123),
                json!({}),
                "subscription",
                Some("base"),
                Some(123),
            ),
            (
                json!(false),
                json!(123),
                json!({}),
                "subscription",
                Some("base"),
                Some(0),
            ),
            (
                Value::Null,
                json!(true),
                json!({}),
                "subscription",
                Some("base"),
                Some(1),
            ),
            (
                json!(0.5),
                Value::Null,
                json!({}),
                "subscription",
                Some("base"),
                None,
            ),
        ] {
            let event: Event = serde_json::from_value(json!({
                "id":"evt_subscription", "type":"customer.subscription.updated",
                "data":{"object":{
                    "metadata":{"cyberdyne_product":"subscription","cyberdyne_plan":"base"},
                    "current_period_end":top,
                    "items":{"data":[
                        {"price":{"metadata":item_metadata},"current_period_end":first},
                        {"current_period_end":999}
                    ]}
                }}
            }))
            .unwrap();
            assert_eq!(event.product(), Some((product, plan)));
            assert_eq!(
                event.expires().unwrap().map(|date| date.timestamp()),
                expiry
            );
        }
    }

    async fn billing_fixture() -> PgPool {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE stripe_events(event_id text PRIMARY KEY,status text,processed_at timestamptz,reason text);
            CREATE TEMP TABLE users(id uuid PRIMARY KEY);
            CREATE TEMP TABLE oauth_clients(client_id text,active bool,registration_source text,allowed_audiences jsonb,redirect_uris jsonb,post_logout_redirect_uris jsonb);
            CREATE TEMP TABLE products(key text,active bool);
            CREATE TEMP TABLE stripe_customers(id uuid,user_id uuid,stripe_customer_id text UNIQUE);
            CREATE TEMP TABLE entitlements(id uuid PRIMARY KEY,user_id uuid,product_key text,plan text,expires_at timestamptz,source text,external_ref text,
                status text DEFAULT 'active',revoked_at timestamptz,updated_at timestamptz);")
            .execute(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn informational_events_complete_while_the_payment_reference_is_locked()
    -> sqlx::Result<()> {
        let pool = billing_fixture().await;
        let reference = Uuid::new_v4().to_string();
        let other = PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut owner = other.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('stripe-reference'),hashtext($1))")
            .bind(&reference)
            .execute(&mut *owner)
            .await?;
        sqlx::query("SET lock_timeout = '1s'")
            .execute(&pool)
            .await?;
        for (kind, handled) in [("invoice.created", false), ("charge.refunded", true)] {
            let notification: Event = serde_json::from_value(json!({
                "id":kind, "type":kind, "data":{"object":{"payment_intent":reference,"refunded":false}}
            })).unwrap();
            assert_eq!(
                ledger::process(&pool, &notification, false).await?,
                Some(handled)
            );
            assert_eq!(
                ledger::process(&pool, &notification, false).await?,
                Some(false)
            );
        }
        let statuses: Vec<String> = sqlx::query_scalar("SELECT status FROM stripe_events")
            .fetch_all(&pool)
            .await?;
        assert_eq!(statuses, ["processed", "processed"]);
        owner.rollback().await
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn signed_checkout_can_be_replayed_after_its_product_is_registered() {
        let pool = billing_fixture().await;
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES($1)")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        let mut event:Event=serde_json::from_value(json!({"id":"evt_sample","type":"checkout.session.completed","data":{"object":{
            "customer":"cus_sample","client_reference_id":user,"metadata":{"cyberdyne_product":"reports"},"payment_intent":"pi_sample"
        }}})).unwrap();
        assert_eq!(
            ledger::process(&pool, &event, false).await.unwrap(),
            Some(false)
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT status FROM stripe_events")
                .fetch_one(&pool)
                .await
                .unwrap(),
            "deferred"
        );
        sqlx::query("INSERT INTO products VALUES('reports',true)")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            ledger::process(&pool, &event, false).await.unwrap(),
            Some(true)
        );
        assert_eq!(
            ledger::process(&pool, &event, false).await.unwrap(),
            Some(false)
        );
        event.id = "evt_refund".into();
        event.kind = "charge.refunded".into();
        event
            .data
            .object
            .fields
            .insert("refunded".into(), Value::Bool(true));
        assert_eq!(
            ledger::process(&pool, &event, false).await.unwrap(),
            Some(true)
        );
        let rows = sqlx::query_as::<_, (String, String, String)>(
            "SELECT source,status,external_ref FROM entitlements",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            [("stripe".into(), "revoked".into(), "pi_sample".into())]
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_deferred_subscription_upgrade_can_resume_after_checkout() -> sqlx::Result<()> {
        let pool = billing_fixture().await;
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES($1)")
            .bind(user)
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO products VALUES('library',true)")
            .execute(&pool)
            .await?;

        let event = |id: &str, kind: &str, object: Value| -> Event {
            serde_json::from_value(json!({"id":id,"type":kind,"data":{"object":object}})).unwrap()
        };
        let upgrade = event(
            "change",
            "customer.subscription.updated",
            json!({
                "id":"sub", "customer":"reader", "items":{"data":[{
                    "current_period_end":2_000_000_000,
                    "price":{"metadata":{"cyberdyne_product":"library","cyberdyne_plan":"plus"}}
                }]}
            }),
        );
        let checkout = event(
            "checkout",
            "checkout.session.completed",
            json!({
                "subscription":"sub", "customer":"reader", "client_reference_id":user,
                "metadata":{"cyberdyne_product":"library","cyberdyne_plan":"basic"}
            }),
        );
        let invoice = event(
            "invoice",
            "invoice.created",
            json!({"customer":"reader","subscription":"sub"}),
        );
        let cancel = event(
            "cancel",
            "customer.subscription.deleted",
            json!({"id":"sub","customer":"reader"}),
        );
        for (notification, handled) in [
            (&upgrade, false),
            (&checkout, true),
            (&invoice, false),
            (&upgrade, true),
            (&upgrade, false),
        ] {
            assert_eq!(
                ledger::process(&pool, notification, false).await?,
                Some(handled)
            );
        }
        let plans = sqlx::query_as::<_, (String, String, Option<i64>)>(
            "SELECT plan,status,extract(epoch FROM expires_at)::bigint FROM entitlements
             WHERE user_id=$1 AND external_ref='sub' ORDER BY plan",
        )
        .bind(user)
        .fetch_all(&pool)
        .await?;
        assert_eq!(
            plans,
            [
                ("basic".into(), "revoked".into(), None),
                ("plus".into(), "active".into(), Some(2_000_000_000))
            ]
        );
        assert_eq!(ledger::process(&pool, &cancel, false).await?, Some(true));
        assert_eq!(ledger::process(&pool, &cancel, false).await?, Some(false));
        let revoked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM entitlements WHERE status='revoked'")
                .fetch_one(&pool)
                .await?;
        let processed: i64 =
            sqlx::query_scalar("SELECT count(*) FROM stripe_events WHERE status='processed'")
                .fetch_one(&pool)
                .await?;
        assert_eq!((revoked, processed), (2, 4));
        Ok(())
    }
}
