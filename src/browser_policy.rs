//! Project committed browser-origin policy into CORS, CSRF and OAuth redirect checks.
use std::{collections::BTreeSet, error::Error};
use tokio::sync::watch;

type Origins = BTreeSet<String>;
pub(crate) type OriginCatalog = watch::Receiver<Origins>;

pub(crate) struct BrowserOrigins {
    cors: Origins,
    redirects: Origins,
}

pub(crate) struct BrowserPolicy {
    base: BrowserOrigins,
    cors: watch::Sender<Origins>,
    redirects: watch::Sender<Origins>,
}

impl BrowserPolicy {
    pub(crate) fn configured() -> Result<(Self, OriginCatalog, OriginCatalog), Box<dyn Error>> {
        let base = BrowserOrigins {
            cors: crate::cors::configured_origins()?,
            redirects: crate::external_oauth::configured_redirects()?,
        };
        let (cors, allowed_origins) = watch::channel(base.cors.clone());
        let (redirects, allowed_redirects) = watch::channel(base.redirects.clone());
        Ok((
            Self {
                base,
                cors,
                redirects,
            },
            allowed_origins,
            allowed_redirects,
        ))
    }

    pub(crate) async fn read(
        &self,
        conn: &mut sqlx::PgConnection,
    ) -> Result<BrowserOrigins, sqlx::Error> {
        let rows = sqlx::query_as::<_, (String, bool, String)>(
            "SELECT origin,cors,fragment_redirect_uris FROM oauth_web_origins WHERE active",
        )
        .fetch_all(conn)
        .await?;
        let mut cors = self.base.cors.clone();
        let mut redirects = self.base.redirects.clone();
        for (origin, allowed, targets) in rows {
            if allowed && origin != "*" {
                cors.insert(origin);
            }
            redirects.extend(targets.split_whitespace().map(str::to_owned));
        }
        Ok(BrowserOrigins { cors, redirects })
    }

    pub(crate) fn publish(&self, origins: BrowserOrigins) {
        self.cors.send_replace(origins.cors);
        self.redirects.send_replace(origins.redirects);
    }
}
