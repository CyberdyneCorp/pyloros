use crate::browser_prompt::encode_query;
use reqwest::Client;
use std::{env, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

mod exchange;
pub use exchange::{ExchangeError, Profile};

#[derive(Clone, Copy)]
enum Kind {
    Google,
    Microsoft,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Microsoft => "microsoft",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::Google => "openid email profile",
            Self::Microsoft => "openid email profile User.Read",
        }
    }
}

struct Remote {
    kind: Kind,
    id: String,
    secret: Zeroizing<String>,
    callback: String,
    authorization: String,
    token: String,
    profile: String,
    http: Client,
}

enum Backend {
    Remote(Box<Remote>),
    Development { kind: Kind, callback: String },
}

pub struct Provider(Backend);

fn provider_http() -> reqwest::ClientBuilder {
    Client::builder()
        .gzip(true)
        .deflate(true)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
}

impl Provider {
    pub(super) fn configured(name: &str, stub: bool) -> Result<Option<Self>, reqwest::Error> {
        let (kind, prefix) = match name {
            "google" => (Kind::Google, "GOOGLE"),
            "microsoft" => (Kind::Microsoft, "MS"),
            _ => return Ok(None),
        };
        let path = format!("/api/v1/auth/oauth/callback/{name}");
        if stub {
            let base = env::var("OAUTH_STUB_CALLBACK_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8000".into());
            return Ok(Some(Self::development(
                kind,
                format!("{}{path}", base.trim_end_matches('/')),
            )));
        }
        let id = env::var(format!("{prefix}_CLIENT_ID")).unwrap_or_default();
        let Ok(secret) = env::var(format!("{prefix}_CLIENT_SECRET")) else {
            return Ok(None);
        };
        if id.is_empty() {
            return Ok(None);
        }
        let callback = env::var(format!("{prefix}_REDIRECT_URI"))
            .unwrap_or_else(|_| format!("http://localhost:8000{path}"));
        let (authorization, token, profile) = match kind {
            Kind::Google => (
                "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
                "https://oauth2.googleapis.com/token".to_owned(),
                "https://openidconnect.googleapis.com/v1/userinfo",
            ),
            Kind::Microsoft => {
                let tenant = env::var("MS_TENANT").unwrap_or_else(|_| "common".into());
                let base = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0");
                (
                    format!("{base}/authorize"),
                    format!("{base}/token"),
                    "https://graph.microsoft.com/v1.0/me",
                )
            }
        };
        let http = provider_http().build()?;
        Ok(Some(Self(Backend::Remote(Box::new(Remote {
            kind,
            id,
            secret: Zeroizing::new(secret),
            callback,
            authorization,
            token,
            profile: profile.to_owned(),
            http,
        })))))
    }
    fn development(kind: Kind, callback: String) -> Self {
        Self(Backend::Development { kind, callback })
    }

    #[cfg(test)]
    pub(super) fn test_google(callback: &str) -> Self {
        Self::development(Kind::Google, callback.to_owned())
    }

    pub(super) fn authorization_url(&self, state: Uuid) -> String {
        let remote = match &self.0 {
            Backend::Remote(remote) => remote,
            Backend::Development { callback, .. } => {
                return format!("{callback}?code=stub-code&state={state}");
            }
        };
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.extend_pairs([
            ("response_type", "code"),
            ("client_id", remote.id.as_str()),
            ("redirect_uri", remote.callback.as_str()),
            ("scope", remote.kind.scope()),
            ("state", &state.to_string()),
        ]);
        match remote.kind {
            Kind::Google => {
                query.extend_pairs([("access_type", "offline"), ("prompt", "consent")]);
            }
            Kind::Microsoft => {
                query.append_pair("response_mode", "query");
            }
        }
        format!("{}?{}", remote.authorization, encode_query(query))
    }
}
