use crate::{
    browser_client::grant::ResourceScopes, discovery::Provider, grant_sessions::GrantSessionIssuer,
};
use chrono::TimeDelta;
use rsa::{
    RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding},
};
use serde::Deserialize;
use sqlx::PgPool;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

pub(crate) type ResourceCatalog = watch::Receiver<Arc<ResourceRegistry>>;
type Audiences = BTreeMap<String, Option<String>>;
#[derive(Clone, Default)]
pub(crate) struct ResourceRegistry {
    pub scopes: ResourceScopes,
    pub audiences: Audiences,
    pub registration_origins: Option<std::collections::BTreeSet<String>>,
}

pub(crate) struct Runtime {
    pub pool: PgPool,
    pub refresh_verifier: crate::mfa_challenges::ChallengeVerifier,
    pub verifier: crate::profile::Verifier,
    pub enforce_revocation: bool,
    pub login_url: Option<String>,
    pub code_ttl: TimeDelta,
    pub consent_page: Option<crate::consent_page::Page>,
    pub signer: GrantSessionIssuer,
    pub oidc_issuer: Option<String>,
    pub access_ttl: TimeDelta,
    pub id_ttl: TimeDelta,
    pub admins: Vec<String>,
    pub production: bool,
    pub resources: watch::Receiver<Arc<ResourceRegistry>>,
}

pub(crate) fn number(name: &str, default: i64) -> Result<i64, Box<dyn Error>> {
    Ok(env::var(name).map_or(Ok(default), |s| s.parse())?)
}

pub(crate) fn lifetime(
    name: &str,
    default: i64,
    seconds: i64,
) -> Result<TimeDelta, Box<dyn Error>> {
    number(name, default)?
        .checked_mul(seconds)
        .filter(|v| *v > 0)
        .and_then(TimeDelta::try_seconds)
        .ok_or_else(|| format!("invalid {name}").into())
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Resource {
    Scopes(Vec<String>),
    Configuration(ResourceOptions),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceOptions {
    #[serde(default)]
    scopes: Vec<String>,
    audience: Option<String>,
}

fn permitted_scope(scope: &str) -> bool {
    !scope.starts_with("admin:")
        && !matches!(
            scope,
            "users:provision" | "directory:read" | "roles:read" | "roles:manage" | "iam:read.tier"
        )
}

impl ResourceRegistry {
    pub(crate) fn registration_scopes(&self) -> BTreeSet<&str> {
        let mut allowed: BTreeSet<_> = ["email", "offline_access", "openid", "profile"].into();
        allowed.extend(
            self.scopes
                .values()
                .flatten()
                .map(String::as_str)
                .filter(|s| permitted_scope(s)),
        );
        allowed
    }
    pub(crate) fn from_env() -> Result<Self, Box<dyn Error>> {
        configured_resources(
            &env::var("OAUTH_PROTECTED_RESOURCES").unwrap_or_default(),
            &env::var("PYLOROS_RESOURCE_SCOPE_CATALOG").unwrap_or_default(),
        )
    }
}

fn configured_resources(
    raw: &str,
    application_scopes: &str,
) -> Result<ResourceRegistry, Box<dyn Error>> {
    let mut registry = ResourceRegistry::default();
    if raw.trim().is_empty() {
        return Ok(registry);
    }
    let known: std::collections::BTreeSet<_> =
        ["openid", "profile", "email", "offline_access", "roles"]
            .into_iter()
            .chain(
                crate::config::PACKAGED_SCOPES
                    .unwrap_or_default()
                    .split_whitespace(),
            )
            .chain(application_scopes.split_whitespace())
            .collect();
    for (uri, entry) in serde_json::from_str::<BTreeMap<String, Resource>>(raw)? {
        let url = url::Url::parse(&uri)?;
        if url.scheme() != "https" || url.host().is_none() || url.fragment().is_some() {
            return Err("invalid protected resource URL".into());
        }
        let (scopes, audience) = match entry {
            Resource::Scopes(scopes) => (scopes, None),
            Resource::Configuration(options) => (options.scopes, options.audience),
        };
        if audience.as_ref().is_some_and(|s| s.trim().is_empty()) {
            return Err("empty protected resource audience".into());
        }
        if let Some(unknown) = scopes.iter().find(|name| !known.contains(name.as_str())) {
            return Err(format!("unknown scope {unknown:?} for protected resource {uri:?}").into());
        }
        registry
            .scopes
            .insert(uri.clone(), scopes.into_iter().collect());
        registry.audiences.insert(uri, audience);
    }
    Ok(registry)
}

async fn load_resources(
    pool: &PgPool,
    base: &ResourceRegistry,
) -> Result<ResourceRegistry, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let registry = base.read(&mut tx).await?;
    tx.commit().await?;
    Ok(registry)
}

impl ResourceRegistry {
    pub(crate) async fn read(&self, conn: &mut sqlx::PgConnection) -> Result<Self, sqlx::Error> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT resource, scopes, audience FROM oauth_protected_resources WHERE active",
        )
        .fetch_all(&mut *conn)
        .await?;
        let mut registry = self.clone();
        for (uri, scopes, audience) in rows {
            if !self.scopes.contains_key(&uri) {
                registry.scopes.insert(
                    uri.clone(),
                    scopes.split_whitespace().map(str::to_owned).collect(),
                );
                registry.audiences.insert(uri, audience);
            }
        }
        if let Some(origins) = &mut registry.registration_origins {
            origins.extend(
                sqlx::query_scalar::<_, String>(
                    "SELECT origin FROM oauth_web_origins WHERE active AND dcr_redirect",
                )
                .fetch_all(&mut *conn)
                .await?,
            );
        }

        Ok(registry)
    }
}

pub(crate) async fn resource_registry(
    pool: PgPool,
    base: ResourceRegistry,
    seconds: u64,
) -> watch::Receiver<Arc<ResourceRegistry>> {
    let (updates, snapshot) = watch::channel(Arc::new(base.clone()));
    if seconds == 0 {
        return snapshot;
    }
    async fn reload(
        pool: &PgPool,
        base: &ResourceRegistry,
        updates: &watch::Sender<Arc<ResourceRegistry>>,
    ) {
        match load_resources(pool, base).await {
            Ok(active) => {
                updates.send_replace(Arc::new(active));
            }
            Err(_) => eprintln!("could not refresh protected resource registry"),
        }
    }
    reload(&pool, &base, &updates).await;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = updates.closed()=> break,
                _ = tokio::time::sleep(Duration::from_secs(seconds))=>reload(&pool,&base,&updates).await,
            }
        }
    });
    snapshot
}

impl Runtime {
    pub async fn load(
        provider: &Provider,
        pool: PgPool,
        production: bool,
        resources: ResourceCatalog,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let (signer, refresh_verifier) = if provider.uses_shared_secret() {
            let Some((identity, verifier)) = crate::login_http::signing_identity(production)?
            else {
                return Ok(None);
            };
            (
                GrantSessionIssuer::with_identity(
                    identity,
                    lifetime("JWT_REFRESH_TOKEN_TTL_DAYS", 30, 86400)?,
                )?,
                verifier,
            )
        } else {
            let Some(pem) = crate::config::pem("JWT_PRIVATE_KEY_PATH", "JWT_PRIVATE_KEY")? else {
                return Ok(None);
            };
            let key = RsaPrivateKey::from_pkcs8_pem(&pem)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))?;
            let kid = provider.signing_identity(&key.to_public_key())?;
            let issuer = provider.session_issuer();
            let signer = GrantSessionIssuer::new(
                issuer.clone(),
                kid.into(),
                pem.as_bytes(),
                lifetime("JWT_REFRESH_TOKEN_TTL_DAYS", 30, 86400)?,
            )?;
            let verifier = crate::mfa_challenges::ChallengeVerifier::rsa(
                &issuer,
                key.to_public_key()
                    .to_public_key_pem(LineEnding::LF)?
                    .as_bytes(),
            )?;
            (signer, verifier)
        };
        let admins = crate::config::admin_emails()?;
        Ok(Some(Self {
            refresh_verifier,
            consent_page: crate::consent_page::Page::configured()?,
            verifier: crate::profile::Verifier::configured(production)?
                .ok_or("missing browser session verification key")?,
            enforce_revocation: crate::config::flag("ENFORCE_TOKEN_REVOCATION")?,
            login_url: ["OIDC_LOGIN_URL", "OAUTH_POST_LOGIN_URL"]
                .into_iter()
                .find_map(|key| env::var(key).ok().filter(|s| !s.is_empty())),
            code_ttl: lifetime("OIDC_CODE_TTL_SECONDS", 60, 1)?,
            access_ttl: lifetime("JWT_ACCESS_TOKEN_TTL_MINUTES", 15, 60)?,
            id_ttl: lifetime("OIDC_ID_TOKEN_TTL_MINUTES", 15, 60)?,
            admins,
            production,
            resources,
            pool,
            signer,
            oidc_issuer: provider.public_base().map(str::to_owned),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_both_resource_configurations_against_the_deployment_catalog() {
        for raw in [
            r#"{"https://service.example":["openid","orders:read"]}"#,
            r#"{"https://service.example":{"scopes":["orders:read"],"audience":"orders"}}"#,
        ] {
            assert!(configured_resources(raw, "orders:read orders:write").is_ok());
            assert!(configured_resources(raw, "orders:reader").is_err());
        }
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn refreshes_scope_ceilings_and_audiences_together() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE oauth_protected_resources(resource text, scopes text, audience text, active boolean)").execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO oauth_protected_resources VALUES
            ('https://fixed.example','database','ignored',true),
            ('https://mutable.example','read write read','custom',true),
            ('https://inactive.example','read',NULL,false)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let base = configured_resources(r#"{"https://fixed.example":["roles"],"https://other.example":{"scopes":[],"audience":"other"}}"#, "").unwrap();
        let snapshot = load_resources(&pool, &base).await.unwrap();
        assert_eq!(snapshot.scopes.len(), 3);
        assert_eq!(
            snapshot.scopes["https://fixed.example"],
            ["roles".into()].into()
        );
        assert_eq!(snapshot.audiences["https://fixed.example"], None);
        assert_eq!(
            snapshot.audiences["https://other.example"].as_deref(),
            Some("other")
        );
        assert_eq!(
            snapshot.scopes["https://mutable.example"],
            ["read".into(), "write".into()].into()
        );
        assert_eq!(
            snapshot.audiences["https://mutable.example"].as_deref(),
            Some("custom")
        );
        sqlx::query("UPDATE oauth_protected_resources SET active=false")
            .execute(&pool)
            .await
            .unwrap();
        let refreshed = load_resources(&pool, &base).await.unwrap();
        assert_eq!(refreshed.scopes, base.scopes);
        assert_eq!(refreshed.audiences, base.audiences);
    }
}
