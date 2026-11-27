//! Read-only provider metadata for a configured issuer.
use std::{collections::BTreeMap, env, error::Error, sync::Arc, time::Duration};

use crate::{
    config::flag,
    token_runtime::{ResourceCatalog, ResourceRegistry},
};
use axum::{Json, Router, extract::State, http::StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

type ConfigError = Box<dyn Error>;
type Document = Result<Json<Value>, Disabled>;

struct Disabled;

pub struct Provider {
    metadata: Value,
    public_jwk: Option<Value>,
    scopes: tokio::sync::watch::Receiver<BTreeMap<String, String>>,
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
        let explicit = env::var("JWT_ALGORITHM").ok();
        let public = match explicit.as_deref() {
            Some("HS256") => None,
            Some("RS256") => Some(
                crate::config::pem("JWT_PUBLIC_KEY_PATH", "JWT_PUBLIC_KEY")?
                    .ok_or("RS256 discovery requires an RSA public key")?,
            ),
            None => crate::config::pem("JWT_PUBLIC_KEY_PATH", "JWT_PUBLIC_KEY")?,
            _ => return Err("unsupported discovery signing algorithm".into()),
        };
        let issuer = env::var("OIDC_ISSUER")?;
        let scopes = env::var("OIDC_SCOPES")
            .unwrap_or_else(|_| "openid profile email offline_access".into());
        let provider = Self::configured(
            &issuer,
            public.as_deref(),
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
        Self::configured(issuer, Some(pem), key_id, scopes, registration, device)
    }

    fn configured(
        issuer: &str,
        pem: Option<&str>,
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
        let public_jwk = if let Some(pem) = pem {
            let public = RsaPublicKey::from_public_key_pem(pem)?;
            let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
            let kid = key_id.unwrap_or_else(|| rsa_kid(&n, &e));
            Some(json!({"alg":"RS256","use":"sig","kty":"RSA","kid":kid,"n":n,"e":e}))
        } else {
            None
        };
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
            scopes
                .split_ascii_whitespace()
                .map(|name| (name.to_owned(), String::new()))
                .collect(),
        )
        .1;
        Ok(Self {
            metadata,
            public_jwk,
            scopes,
        })
    }

    pub(crate) fn scope_catalog(&self) -> tokio::sync::watch::Receiver<BTreeMap<String, String>> {
        self.scopes.clone()
    }

    pub(crate) fn dynamic_registration_enabled(&self) -> bool {
        self.metadata.get("registration_endpoint").is_some()
    }

    pub(crate) fn device_authorization_enabled(&self) -> bool {
        self.metadata.get("device_authorization_endpoint").is_some()
    }

    pub(crate) fn issuer(&self) -> &str {
        self.metadata["issuer"].as_str().expect("configured issuer")
    }

    pub(crate) fn uses_shared_secret(&self) -> bool {
        self.public_jwk.is_none()
    }

    pub(crate) fn signing_identity(&self, key: &RsaPublicKey) -> Result<(&str, &str), ConfigError> {
        let jwk = self
            .public_jwk
            .as_ref()
            .ok_or("RSA discovery key missing")?;
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
        let base = self.scopes.borrow().clone();
        let registry = ScopeRegistry::start(pool, base, None, None, None, interval).await;
        self.scopes = registry.catalog;
    }
}

pub(crate) type ScopeCatalog = tokio::sync::watch::Receiver<BTreeMap<String, String>>;
type ScopeMap = BTreeMap<String, String>;
type Projection = (ScopeMap, tokio::sync::watch::Sender<ScopeMap>);

pub(crate) struct ScopeRegistry {
    pub catalog: ScopeCatalog,
    pub resources: Option<ResourceCatalog>,
    publisher: Arc<ScopePublisher>,
}

struct ScopePublisher {
    browser: Option<crate::browser_policy::BrowserPolicy>,
    projections: Vec<Projection>,
    resources: Option<(
        ResourceRegistry,
        tokio::sync::watch::Sender<Arc<ResourceRegistry>>,
    )>,
    publication: tokio::sync::Mutex<()>,
}

fn projection(base: ScopeMap) -> (Projection, ScopeCatalog) {
    let (sender, receiver) = tokio::sync::watch::channel(base.clone());
    ((base, sender), receiver)
}

impl ScopeRegistry {
    pub(crate) async fn start(
        pool: sqlx::PgPool,
        base: ScopeMap,
        provider: Option<&mut Provider>,
        configured: Option<ResourceRegistry>,
        browser: Option<crate::browser_policy::BrowserPolicy>,
        interval: Duration,
    ) -> Self {
        let (admin, catalog) = projection(base);
        let mut projections = vec![admin];
        let (resource_projection, resources) = configured
            .map(|base| {
                let (sender, receiver) = tokio::sync::watch::channel(Arc::new(base.clone()));
                ((base, sender), receiver)
            })
            .unzip();
        if let Some(provider) = provider {
            let base = provider.scopes.borrow().clone();
            let (discovery, receiver) = projection(base);
            provider.scopes = receiver;
            projections.push(discovery);
        }
        let publisher = Arc::new(ScopePublisher {
            projections,
            resources: resource_projection,
            browser,
            publication: Default::default(),
        });
        if !interval.is_zero() {
            publisher.refresh(&pool).await;
            let worker = publisher.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = worker.projections[0].1.closed() => break,
                        _ = tokio::time::sleep(interval) => worker.refresh(&pool).await,
                    }
                }
            });
        }
        Self {
            catalog,
            publisher,
            resources,
        }
    }

    pub(crate) async fn commit(
        &self,
        mut tx: sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<(), sqlx::Error> {
        let publisher = self.publisher.clone();
        tokio::spawn(async move {
            let _guard = publisher.publication.lock().await;
            let rows = publisher.snapshot(&mut tx).await?;
            tx.commit().await?;
            publisher.publish(rows);
            Ok(())
        })
        .await
        .map_err(|err| sqlx::Error::Protocol(err.to_string()))?
    }
}

struct Snapshot {
    scopes: ScopeMap,
    resources: Option<ResourceRegistry>,
    browser: Option<crate::browser_policy::BrowserOrigins>,
}

impl ScopePublisher {
    async fn snapshot(&self, conn: &mut sqlx::PgConnection) -> Result<Snapshot, sqlx::Error> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT name,coalesce(description,'') FROM oauth_scopes WHERE active",
        )
        .fetch_all(&mut *conn)
        .await?;
        let resources = match &self.resources {
            Some((base, _)) => Some(base.read(conn).await?),
            None => None,
        };
        let browser = match &self.browser {
            Some(policy) => Some(policy.read(conn).await?),
            None => None,
        };
        Ok(Snapshot {
            scopes: rows.into_iter().collect(),
            resources,
            browser,
        })
    }

    fn publish(&self, snapshot: Snapshot) {
        if let (Some(policy), Some(origins)) = (&self.browser, snapshot.browser) {
            policy.publish(origins);
        }
        if let (Some((_, updates)), Some(resources)) = (&self.resources, snapshot.resources) {
            updates.send_replace(Arc::new(resources));
        }
        for (base, updates) in &self.projections {
            let mut effective = base.clone();
            effective.extend(snapshot.scopes.clone());
            updates.send_replace(effective);
        }
    }

    async fn refresh(&self, pool: &sqlx::PgPool) {
        let load = async {
            let mut tx = pool.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *tx)
                .await?;
            let _guard = self.publication.lock().await;
            let rows = self.snapshot(&mut tx).await?;
            tx.commit().await?;
            self.publish(rows);
            Ok::<(), sqlx::Error>(())
        };
        match tokio::time::timeout(Duration::from_secs(3), load).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("Scope catalog refresh failed: {error}"),
            Err(_) => eprintln!("Scope catalog refresh timed out"),
        }
    }
}

type ProviderState = Option<Arc<Provider>>;

impl axum::response::IntoResponse for Disabled {
    fn into_response(self) -> axum::response::Response {
        crate::login_http::problem(StatusCode::NOT_FOUND, "OIDC disabled")
    }
}

async fn metadata(State(provider): State<ProviderState>) -> Document {
    let issuer = provider.as_ref().ok_or(Disabled)?;
    let mut document = issuer.metadata.clone();
    document["scopes_supported"] = json!(issuer.scopes.borrow().keys().collect::<Vec<_>>());
    Ok(Json(document))
}

async fn keys(State(provider): State<ProviderState>) -> Document {
    let provider = provider.as_ref().ok_or(Disabled)?;
    Ok(Json(json!({"keys":provider.public_jwk.as_slice()})))
}

pub fn routes(provider: Option<Provider>) -> Router {
    crate::foundation::get_resource("/.well-known/openid-configuration", metadata)
        .merge(crate::foundation::get_resource(
            "/.well-known/oauth-authorization-server",
            metadata,
        ))
        .merge(crate::foundation::get_resource(
            "/.well-known/jwks.json",
            keys,
        ))
        .with_state(provider.map(Arc::new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_provider_has_no_public_key_and_only_advertises_rsa_id_tokens() {
        let provider = Provider::configured(
            "https://issuer.example",
            None,
            Some("old-key".into()),
            "openid",
            false,
            false,
        )
        .unwrap();
        assert!(provider.uses_shared_secret());
        assert_eq!(
            provider.metadata["id_token_signing_alg_values_supported"],
            json!(["RS256"])
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn local_scope_publication_follows_commit_with_polling_disabled() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let (browser, origins, redirects) =
            crate::browser_policy::BrowserPolicy::configured().unwrap();
        let registry = ScopeRegistry::start(
            pool.clone(),
            BTreeMap::new(),
            None,
            Some(ResourceRegistry::default()),
            Some(browser),
            Duration::ZERO,
        )
        .await;
        let resources = registry.resources.as_ref().unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_scopes (name text, description text, active boolean, UNIQUE(name) DEFERRABLE INITIALLY DEFERRED)")
            .execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO oauth_scopes VALUES ('reports','Reports',true)")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_protected_resources (resource text, scopes text, audience text, active bool)").execute(&mut *tx).await.unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_web_origins (origin text, cors bool, fragment_redirect_uris text, active bool)").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO oauth_protected_resources VALUES ('https://api.example','reports','first',true)").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO oauth_web_origins VALUES ('https://ui.example',true,'https://ui.example/finish',true)").execute(&mut *tx).await.unwrap();
        registry.commit(tx).await.unwrap();
        assert_eq!(registry.catalog.borrow().get("reports").unwrap(), "Reports");
        assert!(origins.borrow().contains("https://ui.example"));
        assert!(redirects.borrow().contains("https://ui.example/finish"));
        assert_eq!(
            resources.borrow().audiences["https://api.example"].as_deref(),
            Some("first")
        );
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO oauth_scopes VALUES ('reports','Changed',true),('other','Other',true)",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("UPDATE oauth_web_origins SET active=false")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("UPDATE oauth_protected_resources SET audience='second'")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(registry.commit(tx).await.is_err());
        assert!(origins.borrow().contains("https://ui.example"));
        assert!(redirects.borrow().contains("https://ui.example/finish"));
        assert_eq!(
            resources.borrow().audiences["https://api.example"].as_deref(),
            Some("first")
        );
        assert_eq!(registry.catalog.borrow().len(), 1);
        assert_eq!(registry.catalog.borrow().get("reports").unwrap(), "Reports");
    }
}
