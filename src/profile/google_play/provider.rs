use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use tokio::sync::{Mutex, OnceCell};
use zeroize::Zeroizing;

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const PLAY_URL: &str = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications";
pub(in crate::profile) struct Provider {
    package: String,
    credentials: Zeroizing<String>,
    client: OnceCell<Client>,
}

struct Client {
    http: reqwest::Client,
    signing: EncodingKey,
    issuer: String,
    key_id: Option<String>,
    token: Mutex<Option<(i64, Zeroizing<String>)>>,
    token_url: String,
    play_url: String,
}
#[derive(Deserialize)]
struct Account {
    client_email: String,
    private_key: String,
    private_key_id: Option<String>,
}
#[derive(Serialize)]
struct Assertion<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'static str,
    iat: i64,
    exp: i64,
}
#[derive(Deserialize)]
struct AccessToken {
    access_token: String,
    expires_in: i64,
}

impl Provider {
    pub(in crate::profile) fn configured() -> Result<Option<Self>, Box<dyn Error>> {
        if !config::flag("BILLING_ENABLED")? {
            return Ok(None);
        }
        let Some(package) = env::var("GOOGLE_PACKAGE_NAME")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        Ok(env::var("GOOGLE_SERVICE_ACCOUNT_JSON")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|credentials| Self {
                package,
                credentials: Zeroizing::new(credentials),
                client: OnceCell::new(),
            }))
    }
    pub(super) async fn expiry(
        &self,
        token: &str,
        product: &str,
    ) -> Result<DateTime<Utc>, Failure> {
        let client = self
            .client
            .get_or_try_init(|| async { Client::new(&self.credentials) })
            .await?;
        let doc = client.subscription(&self.package, token).await?;
        doc.expiry(product, Utc::now())
    }
}
impl Client {
    fn new(raw: &str) -> Result<Self, Failure> {
        let account: Account = serde_json::from_str(raw).map_err(|_| Failure::Unavailable)?;
        let key = Zeroizing::new(account.private_key);
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| Failure::Unavailable)?,
            signing: EncodingKey::from_rsa_pem(key.as_bytes()).map_err(|_| Failure::Unavailable)?,
            issuer: account.client_email,
            key_id: account.private_key_id,
            token: Mutex::new(None),
            token_url: TOKEN_URL.into(),
            play_url: PLAY_URL.into(),
        })
    }
    async fn access_token(&self) -> Result<Zeroizing<String>, Failure> {
        let mut cached = self.token.lock().await;
        let now = Utc::now().timestamp();
        if let Some((until, token)) = cached.as_ref()
            && *until > now + 60
        {
            return Ok(token.clone());
        }
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.key_id.clone();
        let claims = Assertion {
            iss: &self.issuer,
            scope: "https://www.googleapis.com/auth/androidpublisher",
            aud: TOKEN_URL,
            iat: now,
            exp: now + 3600,
        };
        let assertion = Zeroizing::new(
            encode(&header, &claims, &self.signing).map_err(|_| Failure::Unavailable)?,
        );
        let response = self
            .http
            .post(&self.token_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|_| Failure::Unavailable)?
            .error_for_status()
            .map_err(|_| Failure::Unavailable)?
            .bytes()
            .await
            .map_err(|_| Failure::Unavailable)?;
        let reply: AccessToken =
            serde_json::from_slice(&response).map_err(|_| Failure::Unavailable)?;
        if reply.access_token.is_empty() || reply.expires_in <= 0 {
            return Err(Failure::Unavailable);
        }
        let token = Zeroizing::new(reply.access_token);
        *cached = Some((now.saturating_add(reply.expires_in), token.clone()));
        Ok(token)
    }
    async fn subscription(&self, package: &str, token: &str) -> Result<Subscription, Failure> {
        if matches!(token, "." | "..") {
            return Err(Failure::Invalid);
        }
        let mut url = url::Url::parse(&self.play_url).map_err(|_| Failure::Unavailable)?;
        url.path_segments_mut()
            .map_err(|_| Failure::Unavailable)?
            .extend([package, "purchases", "subscriptionsv2", "tokens", token]);
        let access = self.access_token().await?;
        let response = self
            .http
            .get(url)
            .bearer_auth(access.as_str())
            .send()
            .await
            .map_err(|_| Failure::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(Failure::Invalid);
        }
        let body = response.bytes().await.map_err(|_| Failure::Unavailable)?;
        serde_json::from_slice(&body).map_err(|_| Failure::Unavailable)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscription {
    subscription_state: String,
    line_items: Vec<Item>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    product_id: String,
    expiry_time: Option<String>,
}
impl Subscription {
    fn expiry(&self, product: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, Failure> {
        if !matches!(
            self.subscription_state.as_str(),
            "SUBSCRIPTION_STATE_ACTIVE"
                | "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"
                | "SUBSCRIPTION_STATE_CANCELED"
        ) {
            return Err(Failure::Invalid);
        }
        self.line_items
            .iter()
            .filter(|i| i.product_id == product)
            .filter_map(|i| i.expiry_time.as_ref()?.parse::<DateTime<Utc>>().ok())
            .filter(|expiry| *expiry > now)
            .max()
            .ok_or(Failure::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription(state: &str) -> Subscription {
        serde_json::from_value(json!({
            "subscriptionState": format!("SUBSCRIPTION_STATE_{state}"),
            "lineItems": [
                {"productId":"other", "expiryTime":"2033-01-01T00:00:00Z"},
                {"productId":"monthly", "expiryTime":"2031-01-01T00:00:00Z"},
                {"productId":"monthly", "expiryTime":"2030-01-01T00:00:00Z"},
                {"productId":"expired", "expiryTime":"2020-01-01T00:00:00Z"},
                {"productId":"pending"}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn eligible_states_use_latest_matching_expiry() {
        let now = "2029-01-01T00:00:00Z".parse().unwrap();
        let expected: DateTime<Utc> = "2031-01-01T00:00:00Z".parse().unwrap();
        for state in ["ACTIVE", "IN_GRACE_PERIOD", "CANCELED"] {
            assert_eq!(
                subscription(state).expiry("monthly", now).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn requires_current_access_to_the_selected_product() {
        let now = "2029-01-01T00:00:00Z".parse().unwrap();
        for product in ["missing", "expired", "pending"] {
            assert!(matches!(
                subscription("ACTIVE").expiry(product, now),
                Err(Failure::Invalid)
            ));
        }
        for state in ["PENDING", "ON_HOLD", "PAUSED", "EXPIRED", "UNKNOWN"] {
            assert!(matches!(
                subscription(state).expiry("monthly", now),
                Err(Failure::Invalid)
            ));
        }
    }
}
