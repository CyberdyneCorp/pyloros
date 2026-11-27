//! Signed Stripe notifications and transactional fulfillment.
use super::*;
use axum::body::Bytes;
use ring::hmac;
use serde_json::Value;
mod ledger;

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
    let Ok(event) = serde_json::from_slice::<Event>(&body) else {
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
    object: serde_json::Map<String, Value>,
}

impl Event {
    fn text(&self, k: &str) -> Option<&str> {
        self.data.object.get(k)?.as_str()
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
    fn item(&self) -> Option<&Value> {
        self.data.object.get("items")?.get("data")?.get(0)
    }
    fn product(&self) -> Option<(&str, Option<&str>)> {
        let price = self.item().and_then(|v| v.pointer("/price/metadata"));
        [price, self.data.object.get("metadata")]
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
        let seconds = self
            .data
            .object
            .get("current_period_end")
            .and_then(Value::as_i64)
            .or_else(|| self.item()?.get("current_period_end")?.as_i64());
        seconds
            .map(|s| {
                DateTime::from_timestamp(s, 0)
                    .ok_or_else(|| sqlx::Error::Protocol("invalid billing timestamp".into()))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn signed_checkout_can_be_replayed_after_its_product_is_registered() {
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
}
