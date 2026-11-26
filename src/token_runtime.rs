use crate::{discovery::Provider, grant_sessions::GrantSessionIssuer};
use chrono::TimeDelta;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use sqlx::PgPool;
use std::{collections::BTreeMap, env, error::Error, sync::Arc, time::Duration};
use tokio::sync::watch;

type Audiences = BTreeMap<String, Option<String>>;
pub(crate) struct Runtime {
    pub pool: PgPool,
    pub signer: GrantSessionIssuer,
    pub access_ttl: TimeDelta,
    pub id_ttl: TimeDelta,
    pub admins: Vec<String>,
    pub production: bool,
    pub trusted_proxies: usize,
    pub audiences: watch::Receiver<Arc<Audiences>>,
}

fn number(name: &str, default: i64) -> Result<i64, Box<dyn Error>> {
    Ok(env::var(name).map_or(Ok(default), |s| s.parse())?)
}

fn lifetime(name: &str, default: i64, seconds: i64) -> Result<TimeDelta, Box<dyn Error>> {
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
    #[serde(default, rename = "scopes")]
    _scopes: Vec<String>,
    audience: Option<String>,
}

fn env_audiences() -> Result<Audiences, Box<dyn Error>> {
    let raw = env::var("OAUTH_PROTECTED_RESOURCES").unwrap_or_default();
    let mut audiences = Audiences::new();
    if raw.trim().is_empty() {
        return Ok(audiences);
    }
    for (uri, entry) in serde_json::from_str::<BTreeMap<String, Resource>>(&raw)? {
        let url = url::Url::parse(&uri)?;
        if url.scheme() != "https" || url.host().is_none() || url.fragment().is_some() {
            return Err("invalid protected resource URL".into());
        }
        let audience = match entry {
            Resource::Scopes(_scopes) => None,
            Resource::Configuration(options) => options.audience,
        };
        if audience.as_ref().is_some_and(|s| s.trim().is_empty()) {
            return Err("empty protected resource audience".into());
        }
        audiences.insert(uri, audience);
    }
    Ok(audiences)
}

async fn audience_registry(
    pool: PgPool,
    base: Audiences,
    seconds: u64,
) -> watch::Receiver<Arc<Audiences>> {
    let (updates, snapshot) = watch::channel(Arc::new(base.clone()));
    if seconds == 0 {
        return snapshot;
    }
    async fn reload(pool: &PgPool, base: &Audiences, updates: &watch::Sender<Arc<Audiences>>) {
        match sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT resource,audience FROM oauth_protected_resources WHERE active",
        )
        .fetch_all(pool)
        .await
        {
            Ok(rows) => {
                let mut active: Audiences = rows.into_iter().collect();
                active.extend(base.clone());
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
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let Some(pem) = crate::config::pem("JWT_PRIVATE_KEY_PATH", "JWT_PRIVATE_KEY")? else {
            return Ok(None);
        };
        if env::var("JWT_ALGORITHM").is_ok_and(|s| s != "RS256") {
            return Err("code issuance requires RS256".into());
        }
        let key =
            RsaPrivateKey::from_pkcs8_pem(&pem).or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))?;
        let (issuer, kid) = provider.signing_identity(&key.to_public_key())?;
        let signer = GrantSessionIssuer::new(
            issuer.into(),
            kid.into(),
            pem.as_bytes(),
            lifetime("JWT_REFRESH_TOKEN_TTL_DAYS", 30, 86400)?,
        )?;
        let list = env::var("ADMIN_EMAIL_LIST").unwrap_or_default();
        let admins = if list.trim_start().starts_with('[') {
            serde_json::from_str(&list)?
        } else {
            list.split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect()
        };
        Ok(Some(Self {
            access_ttl: lifetime("JWT_ACCESS_TOKEN_TTL_MINUTES", 15, 60)?,
            id_ttl: lifetime("OIDC_ID_TOKEN_TTL_MINUTES", 15, 60)?,
            admins,
            production,
            trusted_proxies: number("TRUSTED_PROXY_COUNT", 0)?.try_into()?,
            audiences: audience_registry(
                pool.clone(),
                env_audiences()?,
                number("OAUTH_REGISTRY_REFRESH_SECONDS", 30)?.try_into()?,
            )
            .await,
            pool,
            signer,
        }))
    }
}
