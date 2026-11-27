//! Resolve the destination before redirecting an OAuth authorization request.
pub mod grant;
use axum::http::uri::Authority;
use sqlx::{Postgres, Transaction};

#[derive(Debug, PartialEq)]
pub struct BrowserClient {
    pub(crate) id: String,
    pub(crate) callback: String,
    pub name: String,
    pub trusted: bool,
    pub dynamic: bool,
    pub grant_types: String,
    pub scopes: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("missing client_id")]
    Missing,
    #[error("unknown or inactive client")]
    Inactive,
    #[error("redirect_uri not registered for this client")]
    Callback,
    #[error("OAuth client registry unavailable")]
    Database(#[from] sqlx::Error),
}

pub async fn resolve(
    tx: &mut Transaction<'_, Postgres>,
    id: Option<&str>,
    callback: Option<&str>,
) -> Result<BrowserClient, ClientError> {
    let id = id.filter(|s| !s.is_empty()).ok_or(ClientError::Missing)?;
    let row=sqlx::query_as::<_,(String,bool,bool,bool,String,String,Option<sqlx::types::Json<Vec<String>>>)>(
        "SELECT name,trusted,registration_source='dynamic',client_type='public',grant_types,allowed_scopes,redirect_uris
        FROM oauth_clients WHERE client_id=$1 AND active FOR SHARE"
    ).bind(id).fetch_optional(&mut **tx).await?.ok_or(ClientError::Inactive)?;
    let (name, trusted, dynamic, public, grant_types, scopes, uris) = row;
    let callback = callback
        .filter(|s| !s.is_empty())
        .ok_or(ClientError::Callback)?;
    let registered = uris.is_some_and(|uris| {
        uris.iter()
            .any(|uri| matches_callback(uri, callback, public))
    });
    if !registered {
        return Err(ClientError::Callback);
    }
    Ok(BrowserClient {
        id: id.into(),
        callback: callback.into(),
        name,
        trusted,
        dynamic,
        grant_types,
        scopes,
    })
}

fn matches_callback(registered: &str, requested: &str, public: bool) -> bool {
    if registered == requested {
        return true;
    }
    public
        && loopback(registered)
            .zip(loopback(requested))
            .is_some_and(|(a, b)| a == b)
}

// URL normalization can collapse distinct paths and numeric host spellings.
// Compare the original path and query and parse only the host and port.
fn loopback(uri: &str) -> Option<(&'static str, &str, &str)> {
    if uri.contains(['#', '\\']) || uri.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return None;
    }
    let (scheme, rest) = uri.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") {
        return None;
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return None;
    }
    let parsed: Authority = authority.parse().ok()?;
    let host = parsed.host();
    let host_len = host.len();
    let canonical = match host {
        "127.0.0.1" => "127.0.0.1",
        "[::1]" => "[::1]",
        name if name.eq_ignore_ascii_case("localhost") => "localhost",
        _ => return None,
    };
    let suffix = &authority[host_len..];
    if !suffix.is_empty() {
        let port = suffix.strip_prefix(':')?;
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if !port.is_empty() {
            port.parse::<u16>().ok()?;
        }
    }
    let tail = &rest[end..];
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    Some((canonical, path, query))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn port_exception_preserves_callback_identity() {
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let registered = format!("http://{host}/callback?q=1");
            let requested = format!("http://{host}:54321/callback?q=1");
            assert!(matches_callback(&registered, &requested, true));
            assert!(!matches_callback(&registered, &requested, false));
        }
        for candidate in [
            "http://localhost/callback",
            "http://127.0.0.1/a/../callback",
            "http://127.0.0.1/%63allback",
            "http://127.0.0.1:70000/callback",
            "http://127.0.0.1:bad/callback",
            "http://127.0.0.1/callback?x=1",
            "http://127.0.0.1/callback#section",
            "https://127.0.0.1/callback",
        ] {
            assert!(!matches_callback(
                "http://127.0.0.1/callback",
                candidate,
                true
            ));
        }
    }
}

#[cfg(test)]
mod database_tests {
    use super::*;
    use sqlx::PgPool;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn client_and_callback_are_validated_before_returning_policy() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE oauth_clients(client_id text,name text,active bool,trusted bool,registration_source text,client_type text,grant_types text,allowed_scopes text,redirect_uris jsonb);
            INSERT INTO oauth_clients VALUES ('app','Native',true,false,'dynamic','public','authorization_code','openid','[\"http://[::1]/cb\"]'),
            ('service','Service',true,true,'admin','confidential','client_credentials','profile',null),
            ('disabled','Disabled',false,true,'admin','public','authorization_code','openid','[\"http://localhost/cb\"]')")
            .execute(&mut *tx).await.unwrap();
        let cb = Some("http://[::1]:9876/cb");
        assert!(matches!(
            resolve(&mut tx, None, cb).await,
            Err(ClientError::Missing)
        ));
        assert!(matches!(
            resolve(&mut tx, Some("disabled"), cb).await,
            Err(ClientError::Inactive)
        ));
        assert!(matches!(
            resolve(&mut tx, Some("service"), cb).await,
            Err(ClientError::Callback)
        ));
        assert!(matches!(
            resolve(&mut tx, Some("app"), None).await,
            Err(ClientError::Callback)
        ));
        let client = resolve(&mut tx, Some("app"), cb).await.unwrap();
        assert_eq!(
            client,
            BrowserClient {
                id: "app".into(),
                callback: "http://[::1]:9876/cb".into(),
                name: "Native".into(),
                trusted: false,
                dynamic: true,
                grant_types: "authorization_code".into(),
                scopes: "openid".into()
            }
        );
    }
}
