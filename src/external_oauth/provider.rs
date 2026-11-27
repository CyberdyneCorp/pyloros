use crate::browser_prompt::encode_query;
use std::env;
use uuid::Uuid;

pub(super) enum Provider {
    Stub(String),
    Google {
        id: String,
        callback: String,
    },
    Microsoft {
        id: String,
        callback: String,
        tenant: String,
    },
}

impl Provider {
    pub(super) fn configured(name: &str, stub: bool) -> Option<Self> {
        let callback_path = format!("/api/v1/auth/oauth/callback/{name}");
        if stub {
            let base = env::var("OAUTH_STUB_CALLBACK_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8000".into());
            return Some(Self::Stub(format!(
                "{}{callback_path}",
                base.trim_end_matches('/')
            )));
        }
        let prefix = if name == "google" { "GOOGLE" } else { "MS" };
        let key = format!("{prefix}_CLIENT_ID");
        if !crate::login_methods::provider_configured(&key, &format!("{prefix}_CLIENT_SECRET")) {
            return None;
        }
        let id = env::var(key).ok()?;
        let callback = env::var(format!("{prefix}_REDIRECT_URI"))
            .unwrap_or_else(|_| format!("http://localhost:8000{callback_path}"));
        Some(if name == "google" {
            Self::Google { id, callback }
        } else {
            Self::Microsoft {
                id,
                callback,
                tenant: env::var("MS_TENANT").unwrap_or_else(|_| "common".into()),
            }
        })
    }

    pub(super) fn authorization_url(&self, state: Uuid) -> String {
        let state = state.to_string();
        let (url, id, callback, scope, extra) = match self {
            Self::Stub(callback) => return format!("{callback}?code=stub-code&state={state}"),
            Self::Google { id, callback } => (
                "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
                id,
                callback,
                "openid email profile",
                [("access_type", "offline"), ("prompt", "consent")].as_slice(),
            ),
            Self::Microsoft {
                id,
                callback,
                tenant,
            } => (
                format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"),
                id,
                callback,
                "openid email profile User.Read",
                [("response_mode", "query")].as_slice(),
            ),
        };
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.extend_pairs([
            ("response_type", "code"),
            ("client_id", id.as_str()),
            ("redirect_uri", callback.as_str()),
            ("scope", scope),
            ("state", &state),
        ]);
        query.extend_pairs(extra.iter().copied());
        format!("{url}?{}", encode_query(query))
    }
}
