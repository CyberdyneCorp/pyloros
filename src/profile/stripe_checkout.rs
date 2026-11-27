//! Authenticated creation of hosted Stripe Checkout sessions.
use super::*;
use crate::{login_http::problem, request_json::fields};
use axum::body::Bytes;
use zeroize::Zeroizing;

const ENDPOINT: &str = "https://api.stripe.com/v1/checkout/sessions";
const API_VERSION: &str = "2026-06-24.dahlia";

pub(super) struct Provider {
    http: reqwest::Client,
    endpoint: String,
    key: Zeroizing<String>,
}

impl Provider {
    pub(super) fn configured() -> Result<Option<Self>, Box<dyn Error>> {
        if !config::flag("BILLING_ENABLED")? {
            return Ok(None);
        }
        let Some(key) = env::var("STRIPE_API_KEY").ok().filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(80))
            .build()?;
        Ok(Some(Self {
            http,
            endpoint: ENDPOINT.into(),
            key: Zeroizing::new(key),
        }))
    }

    async fn create(&self, session: &Checkout, user: Uuid, customer: Option<&str>) -> Response {
        let reference = user.to_string();
        let mut form = vec![
            ("mode", session.mode.as_str()),
            ("line_items[0][price]", session.price.as_str()),
            ("line_items[0][quantity]", "1"),
            ("client_reference_id", &reference),
            ("success_url", &session.success),
            ("cancel_url", &session.cancel),
            ("metadata[cyberdyne_product]", &session.product),
            (
                "metadata[cyberdyne_plan]",
                session.plan.as_deref().unwrap_or(""),
            ),
        ];
        if let Some(customer) = customer.filter(|c| !c.is_empty()) {
            form.push(("customer", customer))
        }
        let request = self
            .http
            .post(&self.endpoint)
            .bearer_auth(self.key.as_str())
            .header("Stripe-Version", API_VERSION)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .form(&form);
        let response = match send(request).await {
            Some(r) if r.status().is_success() => r,
            _ => return internal(),
        };
        let Ok(bytes) = response.bytes().await else {
            return internal();
        };
        let Ok(result) = serde_json::from_slice::<ProviderSession>(&bytes) else {
            return internal();
        };
        match (result.id.text(), result.url.text()) {
            (Ok(id), Ok(url)) => Json(json!({"id":id,"url":url})).into_response(),
            _ => internal(),
        }
    }
}

// The provider can complete the operation even when its first response is lost.
// Clone the complete form request so every attempt retains the same idempotency key.
async fn send(request: reqwest::RequestBuilder) -> Option<reqwest::Response> {
    for retry in 0..=2 {
        let result = request.try_clone()?.send().await;
        let delay = match &result {
            Ok(response) if retry_status(response) => response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()?.trim().parse::<u64>().ok())
                .filter(|n| *n <= 60)
                .unwrap_or(0),
            Err(error) if error.is_request() || error.is_timeout() => 0,
            _ => return result.ok(),
        };
        if retry == 2 {
            return result.ok();
        }
        let base: f64 = if retry == 0 {
            0.5
        } else {
            rand::Rng::gen_range(&mut rand::thread_rng(), 0.5..=1.0)
        };
        drop(result);
        tokio::time::sleep(std::time::Duration::from_secs_f64(base.max(delay as f64))).await;
    }
    None
}

fn retry_status(response: &reqwest::Response) -> bool {
    match response
        .headers()
        .get("stripe-should-retry")
        .and_then(|h| h.to_str().ok())
    {
        Some("true") => true,
        Some("false") => false,
        _ => response.status() == StatusCode::CONFLICT || response.status().is_server_error(),
    }
}

#[derive(Deserialize)]
struct ProviderSession {
    id: ProviderField,
    url: ProviderField,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct ProviderField(Box<serde_json::value::RawValue>);
impl ProviderField {
    fn text(&self) -> serde_json::Result<String> {
        if self.0.get().starts_with('"') {
            serde_json::from_str(self.0.get())
        } else {
            crate::json_representation::representation(&self.0)
        }
    }
}

#[derive(Debug)]
struct Checkout {
    price: String,
    product: String,
    plan: Option<String>,
    mode: String,
    success: String,
    cancel: String,
}
impl Checkout {
    fn read(raw: &serde_json::value::RawValue) -> Result<Self, Box<Response>> {
        let submitted = fields::object_fields(raw)?;
        let body = fields::project_scalars(
            raw,
            &submitted,
            &[
                "price_id",
                "product_key",
                "plan",
                "mode",
                "success_url",
                "cancel_url",
            ],
        );
        Self::parse(&body).map_err(|issues| {
            fields::invalid(
                issues
                    .into_iter()
                    .map(|issue| {
                        let input = issue["loc"][1]
                            .as_str()
                            .and_then(|key| submitted.get(key).copied())
                            .unwrap_or(raw);
                        (issue, input)
                    })
                    .collect(),
            )
        })
    }

    fn parse(body: &Value) -> Result<Self, Vec<Value>> {
        let body = admin_fields::object(body)?;
        let mut f = admin_fields::Fields {
            body,
            issues: Vec::new(),
        };
        let price = f.string("price_id", Some(255), true);
        let product = f.string("product_key", Some(64), true);
        let plan = f.string("plan", Some(64), false);
        let mode = match body.get("mode") {
            None => "subscription",
            Some(value) => match value.as_str() {
                Some(m @ ("subscription" | "payment")) => m,
                _ => {
                    let expected = "'subscription' or 'payment'";
                    f.issues.push(json!({"type":"literal_error","loc":["body","mode"],"msg":format!("Input should be {expected}"),"input":value,"ctx":{"expected":expected}}));
                    ""
                }
            },
        };
        let success = f.string("success_url", Some(2048), true);
        let cancel = f.string("cancel_url", Some(2048), true);
        match (price, product, success, cancel) {
            (Some(price), Some(product), Some(success), Some(cancel)) if f.issues.is_empty() => {
                Ok(Self {
                    price,
                    product,
                    plan,
                    mode: mode.into(),
                    success,
                    cancel,
                })
            }
            _ => Err(f.issues),
        }
    }
}

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    if method != Method::POST {
        return passkeys::post_required();
    }
    let body = match fields::document(&headers, &bytes) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let Some(id) = credential(&headers).and_then(|v| state.verify.as_ref()?.read(v)) else {
        return unauthorized();
    };
    let tx = match authenticated_transaction(&state, &id).await {
        Ok(tx) => tx,
        Err(e) => return *e,
    };
    let Some(body) = body else { return internal() };
    let session = match Checkout::read(&body) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let Some(provider) = &state.stripe_checkout else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"billing not enabled"})),
        )
            .into_response();
    };
    let mut tx = match tx {
        Some(tx) => tx,
        None => match state.pool.begin().await {
            Ok(tx) => tx,
            Err(_) => return internal(),
        },
    };
    match store_products::grantable(&mut tx, &session.product).await {
        Ok(true) => {}
        Ok(false) => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unknown or inactive product",
            );
        }
        Err(_) => return internal(),
    }
    let customer = sqlx::query_scalar::<_, String>(
        "SELECT stripe_customer_id FROM stripe_customers WHERE user_id=$1 LIMIT 1",
    )
    .bind(id.user)
    .fetch_optional(&mut *tx)
    .await;
    let Ok(customer) = customer else {
        return internal();
    };
    if tx.commit().await.is_err() {
        return internal();
    }
    provider
        .create(&session, id.user, customer.as_deref())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;

    #[tokio::test]
    async fn checkout_errors_preserve_original_values_and_field_order() {
        let raw = RawValue::from_string(
            r#"{"price_id":1234567890123456789012345,"plan":false,"mode":"bad","cancel_url":""}"#
                .into(),
        )
        .unwrap();
        let response = Checkout::read(&raw).unwrap_err();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("1234567890123456789012345")
        );
        let errors: Value = serde_json::from_slice(&body).unwrap();
        let keys = errors["detail"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["loc"][1].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "price_id",
                "product_key",
                "plan",
                "mode",
                "success_url",
                "cancel_url"
            ]
        );
    }

    #[tokio::test]
    async fn checkout_passes_product_and_returning_customer_to_provider() {
        use axum::{Form, routing::post};
        use std::collections::HashMap;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let user = Uuid::new_v4();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = Router::new().route(
            "/v1/checkout/sessions",
            post(
                move |State(attempts): State<Arc<std::sync::Mutex<Vec<Uuid>>>>,
                      headers: HeaderMap,
                      Form(form): Form<HashMap<String, String>>| async move {
                    assert_eq!(headers["authorization"], "Bearer sk_test_fixture");
                    assert_eq!(headers["stripe-version"], API_VERSION);
                    let key =
                        Uuid::parse_str(headers["idempotency-key"].to_str().unwrap()).unwrap();
                    let mut seen = attempts.lock().unwrap();
                    seen.push(key);
                    assert_eq!(form["client_reference_id"], user.to_string());
                    assert_eq!(form["metadata[cyberdyne_product]"], "reports");
                    assert_eq!(form["metadata[cyberdyne_plan]"], "");
                    assert_eq!(form["line_items[0][price]"], "price_2");
                    assert_eq!(form["line_items[0][quantity]"], "1");
                    assert_eq!(form["mode"], "subscription");
                    assert_eq!(form["customer"], "cus_returning");
                    if seen.len() == 1 {
                        return StatusCode::CONFLICT.into_response();
                    }
                    Json(json!({"id":"cs_fixture","url":"https://pay.example/fixture"}))
                        .into_response()
                },
            ),
        );
        let app = app.with_state(attempts.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = Provider {
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            endpoint: format!("http://{address}/v1/checkout/sessions"),
            key: Zeroizing::new("sk_test_fixture".into()),
        };
        let input=Checkout::parse(&json!({"price_id":"price_2","product_key":"reports","success_url":"https://app.example/ok","cancel_url":"https://app.example/cancel"})).unwrap();
        let response = provider.create(&input, user, Some("cus_returning")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"id":"cs_fixture","url":"https://pay.example/fixture"})
        );
        let seen = attempts.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], seen[1]);
        server.abort();
    }

    #[tokio::test]
    async fn lost_response_retries_the_same_provider_request() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).await.unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    headers.push_str(&line);
                }
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("idempotency-key: checkout-test")
                );
                let mut body = [0; 3];
                reader.read_exact(&mut body).await.unwrap();
                assert_eq!(&body, b"a=b");
                if attempt == 1 {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                }
            }
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let request = client
            .post(format!("http://{address}/checkout"))
            .header("Idempotency-Key", "checkout-test")
            .body("a=b");
        let response = tokio::time::timeout(std::time::Duration::from_secs(8), send(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        server.await.unwrap();
    }
}
