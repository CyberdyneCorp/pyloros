//! Read-only provider metadata for a configured issuer.
use std::{collections::BTreeSet, env, error::Error, sync::Arc, time::Duration};

use crate::config::flag;
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

type ConfigError = Box<dyn Error>;
type Document = Result<Json<Value>, (StatusCode, Json<Value>)>;

pub struct Provider {
    metadata: Value,
    keys: Value,
    scopes: tokio::sync::watch::Receiver<BTreeSet<String>>,
}

pub(crate) fn rsa_kid(n: &str, e: &str) -> String {
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

impl Provider {
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        if !flag("OIDC_ENABLED")? {
            return Ok(None);
        }
        let pem = crate::config::pem("JWT_PUBLIC_KEY_PATH", "JWT_PUBLIC_KEY")?
            .ok_or("OIDC discovery requires an RSA public key")?;
        let issuer = env::var("OIDC_ISSUER")?;
        let scopes = env::var("OIDC_SCOPES")
            .unwrap_or_else(|_| "openid profile email offline_access".into());
        let provider = Self::new(
            &issuer,
            &pem,
            env::var("JWT_KEY_ID").ok(),
            &scopes,
            flag("OAUTH_DCR_ENABLED")?,
            flag("OAUTH_DEVICE_GRANT_ENABLED")?,
        )?;
        Ok(Some(provider))
    }

    pub fn new(
        issuer: &str,
        pem: &str,
        key_id: Option<String>,
        scopes: &str,
        registration: bool,
        device: bool,
    ) -> Result<Self, ConfigError> {
        let issuer = issuer.trim_end_matches('/');
        let url = Url::parse(issuer)?;
        if !matches!(url.scheme(), "https" | "http")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "OIDC_ISSUER must be an HTTP(S) issuer URL without credentials, query or fragment"
                    .into(),
            );
        }
        let public = RsaPublicKey::from_public_key_pem(pem)?;
        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let kid = key_id.unwrap_or_else(|| rsa_kid(&n, &e));
        let keys = json!({"keys":[{"alg":"RS256","use":"sig","kty":"RSA","kid":kid,"n":n,"e":e}]});
        let base = format!("{issuer}/api/v1/auth");
        let oauth = format!("{base}/oauth2");
        let methods = ["client_secret_basic", "client_secret_post", "none"];
        let mut grants = vec!["authorization_code", "refresh_token", "client_credentials"];
        if device {
            grants.push("urn:ietf:params:oauth:grant-type:device_code");
        }
        let mut metadata = json!({
            "issuer":issuer,"jwks_uri":format!("{issuer}/.well-known/jwks.json"),
            "authorization_endpoint":format!("{oauth}/authorize"),"token_endpoint":format!("{oauth}/token"),
            "introspection_endpoint":format!("{base}/introspect"),"revocation_endpoint":format!("{oauth}/revoke"),
            "userinfo_endpoint":format!("{oauth}/userinfo"),"end_session_endpoint":format!("{oauth}/logout"),
            "response_types_supported":["code"],"grant_types_supported":grants,
            "id_token_signing_alg_values_supported":["RS256"],"subject_types_supported":["public"],
            "code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":methods,
            "revocation_endpoint_auth_methods_supported":methods,
            "claims_supported":["sub","iss","aud","exp","iat","auth_time","amr","nonce","email","email_verified","name","picture","is_admin","entitlements","org","orgs","roles","org_roles","permissions","org_permissions"]
        });
        if device {
            metadata["device_authorization_endpoint"] =
                json!(format!("{oauth}/device_authorization"));
        }
        if registration {
            metadata["registration_endpoint"] = json!(format!("{oauth}/register"));
        }
        let scopes = tokio::sync::watch::channel(
            scopes.split_ascii_whitespace().map(str::to_owned).collect(),
        )
        .1;
        Ok(Self {
            metadata,
            keys,
            scopes,
        })
    }

    pub(crate) fn device_authorization_enabled(&self) -> bool {
        self.metadata.get("device_authorization_endpoint").is_some()
    }

    pub(crate) fn issuer(&self) -> &str {
        self.metadata["issuer"].as_str().expect("configured issuer")
    }

    pub(crate) fn signing_identity(&self, key: &RsaPublicKey) -> Result<(&str, &str), ConfigError> {
        let jwk = &self.keys["keys"][0];
        if jwk["n"] != URL_SAFE_NO_PAD.encode(key.n().to_bytes_be())
            || jwk["e"] != URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())
        {
            return Err("private signing key does not match discovery public key".into());
        }
        Ok((
            self.issuer(),
            jwk["kid"].as_str().expect("configured key identifier"),
        ))
    }

    pub async fn refresh_scopes(&mut self, pool: sqlx::PgPool, interval: Duration) {
        if interval.is_zero() {
            return;
        }
        let base = self.scopes.borrow().clone();
        let (updates, snapshot) = tokio::sync::watch::channel(base.clone());
        self.scopes = snapshot;
        load_scopes(&pool, &base, &updates).await;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = updates.closed() => break,
                    _ = tokio::time::sleep(interval) => load_scopes(&pool, &base, &updates).await,
                }
            }
        });
    }
}

async fn load_scopes(
    pool: &sqlx::PgPool,
    base: &BTreeSet<String>,
    updates: &tokio::sync::watch::Sender<BTreeSet<String>>,
) {
    let read = sqlx::query_scalar::<_, String>("SELECT name FROM oauth_scopes WHERE active")
        .fetch_all(pool);
    match tokio::time::timeout(Duration::from_secs(3), read).await {
        Ok(Ok(rows)) => {
            let mut effective = base.clone();
            effective.extend(rows);
            updates.send_replace(effective);
        }
        Ok(Err(error)) => eprintln!("Scope catalog refresh failed: {error}"),
        Err(_) => eprintln!("Scope catalog refresh timed out"),
    }
}

type ProviderState = Option<Arc<Provider>>;

fn enabled(provider: &ProviderState) -> Result<&Provider, (StatusCode, Json<Value>)> {
    provider.as_deref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"detail":"OIDC disabled"})),
        )
    })
}

async fn metadata(State(provider): State<ProviderState>) -> Document {
    let issuer = enabled(&provider)?;
    let mut document = issuer.metadata.clone();
    document["scopes_supported"] = json!(*issuer.scopes.borrow());
    Ok(Json(document))
}

async fn keys(State(provider): State<ProviderState>) -> Document {
    Ok(Json(enabled(&provider)?.keys.clone()))
}

pub fn routes(provider: Option<Provider>) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(metadata))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/.well-known/jwks.json", get(keys))
        .with_state(provider.map(Arc::new))
}
