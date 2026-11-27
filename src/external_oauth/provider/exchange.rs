use super::{Backend, Kind, Provider, Remote};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Response;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub struct Profile {
    pub provider: &'static str,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("OAuth exchange failed")]
pub struct ExchangeError;

#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    id_token: Option<Value>,
}

impl Provider {
    pub async fn exchange(&self, code: &str) -> Result<Profile, ExchangeError> {
        match &self.0 {
            Backend::Remote(remote) => remote.exchange(code).await,
            Backend::Development { kind, .. } => {
                let name = kind.name();
                Ok(Profile {
                    provider: name,
                    subject: format!("stub-{name}-subject"),
                    email: Some(format!("stub-{name}@example.com")),
                    email_verified: true,
                    name: Some(
                        match kind {
                            Kind::Google => "Stub Google User",
                            Kind::Microsoft => "Stub Microsoft User",
                        }
                        .into(),
                    ),
                    picture: None,
                })
            }
        }
    }
}

async fn body<T: serde::de::DeserializeOwned>(mut response: Response) -> Result<T, ExchangeError> {
    const LIMIT: usize = 1024 * 1024;
    if !response.status().is_success() {
        return Err(ExchangeError);
    }
    let mut bytes = Vec::new();
    while let Some(piece) = response.chunk().await.map_err(|_| ExchangeError)? {
        if piece.len() > LIMIT - bytes.len() {
            return Err(ExchangeError);
        }
        bytes.extend_from_slice(&piece);
    }
    serde_json::from_slice(&bytes).map_err(|_| ExchangeError)
}

impl Remote {
    async fn exchange(&self, code: &str) -> Result<Profile, ExchangeError> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", self.id.as_str()),
            ("client_secret", self.secret.as_str()),
            ("redirect_uri", self.callback.as_str()),
        ];
        if matches!(self.kind, Kind::Microsoft) {
            form.push(("scope", self.kind.scope()));
        }
        let tokens: Tokens = body(
            self.http
                .post(&self.token)
                .form(&form)
                .send()
                .await
                .map_err(|_| ExchangeError)?,
        )
        .await?;
        let response = self
            .http
            .get(&self.profile)
            .bearer_auth(tokens.access_token)
            .send()
            .await
            .map_err(|_| ExchangeError)?;
        let data = body::<Value>(response).await?;
        profile(self.kind, data, tokens.id_token.as_ref())
    }
}

fn profile(kind: Kind, data: Value, id_token: Option<&Value>) -> Result<Profile, ExchangeError> {
    let text = |key: &str| data.get(key).and_then(Value::as_str).map(str::to_owned);
    let (subject, email, verified, name, picture) = match kind {
        Kind::Google => (
            text("sub"),
            text("email"),
            data["email_verified"] == true,
            text("name"),
            text("picture"),
        ),
        Kind::Microsoft => (
            text("id"),
            text("mail")
                .filter(|s| !s.is_empty())
                .or_else(|| text("userPrincipalName")),
            id_token
                .and_then(Value::as_str)
                .is_some_and(microsoft_verified),
            text("displayName"),
            None,
        ),
    };
    Ok(Profile {
        provider: kind.name(),
        subject: subject.filter(|s| !s.is_empty()).ok_or(ExchangeError)?,
        email,
        email_verified: verified,
        name,
        picture,
    })
}

// These claims come exclusively from the provider's HTTPS token endpoint.
fn microsoft_verified(token: &str) -> bool {
    fn claims(token: &str) -> Option<Value> {
        let mut parts = token.split('.');
        let header = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
        serde_json::from_slice::<serde_json::Map<String, Value>>(&header).ok()?;
        let payload = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
        URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
        if parts.next().is_some() {
            return None;
        }
        serde_json::from_slice(&payload).ok()
    }
    let Some(claims) = claims(token) else {
        return false;
    };
    let domain = &claims["xms_edov"];
    claims["tid"] == "9188040d-6c67-4c5b-b112-36a304b66dad"
        || domain == true
        || domain == 1
        || matches!(domain.as_str(), Some("true" | "1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Form, Json, Router,
        http::{HeaderMap, StatusCode},
        routing::{get, post},
    };
    use serde_json::json;
    use std::collections::HashMap;

    fn token(claims: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{header}.{payload}.dGVzdA")
    }

    #[test]
    fn microsoft_email_requires_provider_verification() {
        for (claims, verified) in [
            (json!({"tid":"9188040d-6c67-4c5b-b112-36a304b66dad"}), true),
            (json!({"xms_edov":true}), true),
            (json!({"xms_edov":1}), true),
            (json!({"xms_edov":"true"}), true),
            (json!({"xms_edov":"1"}), true),
            (json!({"xms_edov":"TRUE"}), false),
            (json!({"xms_edov":false}), false),
            (json!({"tid":"enterprise"}), false),
        ] {
            assert_eq!(microsoft_verified(&token(claims)), verified);
        }
        assert!(!microsoft_verified("invalid"));
        let data = json!({"id":"subject","mail":"","userPrincipalName":"upn@example.test"});
        let account = profile(Kind::Microsoft, data, None).unwrap();
        assert_eq!(account.email.as_deref(), Some("upn@example.test"));
        assert!(!account.email_verified);
    }

    #[tokio::test]
    async fn development_profiles_preserve_the_provider_identity() {
        for kind in [Kind::Google, Kind::Microsoft] {
            let provider = Provider::development(kind, "http://localhost/callback".into());
            let result = provider.exchange("sample-code").await.unwrap();
            let name = kind.name();
            assert_eq!(result.provider, name);
            assert_eq!(result.subject, format!("stub-{name}-subject"));
            assert_eq!(result.email, Some(format!("stub-{name}@example.com")));
            assert!(result.email_verified);
        }
    }

    #[test]
    fn verified_google_email_requires_a_boolean_claim_and_stable_subject() {
        for claim in [json!(false), json!("false"), Value::Null] {
            assert!(
                !profile(
                    Kind::Google,
                    json!({"sub":"subject","email_verified":claim}),
                    None
                )
                .unwrap()
                .email_verified
            );
        }
        assert!(profile(Kind::Google, json!({"email_verified":true}), None).is_err());
    }
    #[tokio::test]
    async fn exchange_sends_provider_forms_and_uses_only_the_access_token_for_userinfo() {
        for kind in [Kind::Google, Kind::Microsoft] {
            let app=Router::new()
            .route("/token",post(move |Form(fields):Form<HashMap<String,String>>|async move{
                let mut expected=HashMap::from([("client_id","client"),("code","code"),("client_secret","secret"),("grant_type","authorization_code"),("redirect_uri","https://issuer.example/callback")]);
                if matches!(kind,Kind::Microsoft) {expected.insert("scope",kind.scope());}
                assert_eq!(fields.len(),expected.len());
                for (name,value) in expected {assert_eq!(fields[name],value)}
                Json(json!({"access_token":"fixture-access","id_token":token(json!({"xms_edov":true}))}))
            }))
            .route("/profile",get(move |headers:HeaderMap|async move{
                assert_eq!(headers["authorization"],"Bearer fixture-access");
                Json(match kind {
                    Kind::Google=>json!({"sub":"subject","email":"mail@example.test","email_verified":true,"name":"Example","picture":"https://example.test/photo"}),
                    Kind::Microsoft=>json!({"id":"subject","mail":"mail@example.test","userPrincipalName":"other@example.test","displayName":"Example"})
                })
            }))
            .route("/refuse",post(||async{StatusCode::BAD_REQUEST}))
            .route("/oversize",get(||async{vec![b'x';1024*1024+1]}));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let mut remote = Remote {
                kind,
                id: "client".into(),
                secret: "secret".to_owned().into(),
                callback: "https://issuer.example/callback".into(),
                authorization: String::new(),
                token: format!("{base}/token"),
                profile: format!("{base}/profile"),
                http: reqwest::Client::builder()
                    .no_gzip()
                    .no_deflate()
                    .no_proxy()
                    .build()
                    .unwrap(),
            };
            let account = remote.exchange("code").await.unwrap();
            assert!(account.email_verified);
            assert_eq!(account.email.as_deref(), Some("mail@example.test"));
            assert_eq!(account.subject, "subject");
            assert_eq!(account.name.as_deref(), Some("Example"));
            assert_eq!(account.picture.is_some(), matches!(kind, Kind::Google));
            remote.profile = format!("{base}/oversize");
            assert!(remote.exchange("code").await.is_err());
            remote.token = format!("{base}/refuse");
            assert!(remote.exchange("code").await.is_err());
            server.abort();
        }
    }
}
