use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub(super) struct Settings {
    name: String,
    ttl: i64,
    browser: Vec<String>,
    native: Vec<String>,
    pub(super) digest: String,
    dev: bool,
    secure: bool,
    proxy_peers: Vec<ipnet::IpNet>,
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

// The shared challenge table binds a ceremony to a digest of this ordered JSON document.
fn policy_list(origins: &[String]) -> String {
    let items: Vec<_> = origins.iter().map(|origin| json_string(origin)).collect();
    format!("[{}]", items.join(", "))
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap()
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_string()
            } else {
                c.encode_utf16(&mut [0; 2])
                    .iter()
                    .map(|unit| format!("\\u{unit:04x}"))
                    .collect()
            }
        })
        .collect()
}

impl Settings {
    pub(super) fn configured(rp: &str) -> Result<Self, Box<dyn Error>> {
        let browser = crate::login_methods::configured_origins("PASSKEYS_ORIGINS");
        let native = crate::login_methods::configured_origins("PASSKEYS_NATIVE_ORIGINS");
        let policy = format!(
            "[true, {}, {}, {}]",
            json_string(rp),
            policy_list(&browser),
            policy_list(&native)
        );
        let environment = env::var("APP_ENV").unwrap_or_else(|_| "dev".into());
        let ttl = crate::token_runtime::number("PASSKEYS_CHALLENGE_TTL_SECONDS", 300)?;
        if !(30..=300).contains(&ttl) {
            return Err("invalid PASSKEYS_CHALLENGE_TTL_SECONDS".into());
        }
        let proxy_peers = env::var("FORWARDED_ALLOW_IPS").unwrap_or_else(|_| "127.0.0.1".into());
        let proxy_peers = proxy_peers
            .split(',')
            .map(str::trim)
            .flat_map(|p| {
                if p == "*" {
                    return vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
                }
                p.parse()
                    .ok()
                    .or_else(|| p.parse::<IpAddr>().ok().map(Into::into))
                    .into_iter()
                    .collect()
            })
            .collect();
        Ok(Self {
            name: env::var("PASSKEYS_RP_NAME").unwrap_or_else(|_| "CyberdyneAuth".into()),
            browser,
            native,
            ttl,
            digest: format!("{:x}", Sha256::digest(policy)),
            dev: environment == "dev",
            secure: crate::session_cookies::secure_transport(environment == "production")?,
            proxy_peers,
        })
    }

    pub(super) fn transport(
        &self,
        headers: &HeaderMap,
        peer: IpAddr,
        starting: bool,
    ) -> Option<Transport> {
        let origin = header_value(headers, "origin")?.to_owned();
        let native = header_value(headers, "x-passkey-client") == Some("native");
        let trusted = if native { &self.native } else { &self.browser };
        if !trusted.contains(&origin) {
            return None;
        }
        if native {
            let tls = self.proxy_peers.iter().any(|p| p.contains(&peer))
                && header_value(headers, "x-forwarded-proto") == Some("https");
            if headers
                .get_all(header::COOKIE)
                .iter()
                .any(|v| !v.as_bytes().is_empty())
                || !(self.dev || tls)
            {
                return None;
            }
        }
        let binding = if native {
            header_value(headers, "x-passkey-binding")
                .filter(|_| !starting)
                .map(str::to_owned)
        } else {
            binding_cookie::read(headers).filter(|s| !s.is_empty())
        };
        let secret = binding
            .filter(|s| !s.is_empty())
            .or_else(|| starting.then(|| URL_SAFE_NO_PAD.encode(random_bytes())))?;
        if secret.chars().count() > 128 {
            return None;
        }
        Some(Transport {
            origin,
            secret,
            native,
        })
    }
}

pub(super) struct Transport {
    pub(super) origin: String,
    pub(super) secret: String,
    native: bool,
}

pub(super) async fn issue(
    mut tx: Transaction<'_, Postgres>,
    settings: &Settings,
    id: &Identity,
    session: Uuid,
    rp: &str,
    binding: Transport,
    mfa: bool,
) -> Result<Response, sqlx::Error> {
    if !recent(&mut tx, id, mfa).await? {
        return Ok(problem(
            StatusCode::FORBIDDEN,
            "Recent authentication required",
        ));
    }
    let challenge = random_bytes();
    let enrollment = crate::passkey_ceremonies::Enrollment {
        user: id.user,
        session,
        relying_party: rp,
        origin: &binding.origin,
        binding: &binding.secret,
        policy_digest: &settings.digest,
    };
    let ceremony = enrollment.issue(&mut tx, &challenge, settings.ttl).await?;
    sqlx::query(
        "INSERT INTO passkey_handles(user_id,handle) VALUES($1,$2) ON CONFLICT(user_id) DO NOTHING",
    )
    .bind(id.user)
    .bind(random_bytes().as_slice())
    .execute(&mut *tx)
    .await?;
    let handle: Vec<u8> = sqlx::query_scalar("SELECT handle FROM passkey_handles WHERE user_id=$1")
        .bind(id.user)
        .fetch_one(&mut *tx)
        .await?;
    let keys: Vec<String> = sqlx::query_scalar("SELECT credential_id FROM passkeys WHERE user_id=$1 AND rp_id=$2 AND revoked_at IS NULL ORDER BY created_at")
        .bind(id.user).bind(rp).fetch_all(&mut *tx).await?;
    let exclude: Vec<_> = keys
        .into_iter()
        .map(|key| json!({"type":"public-key","id":key}))
        .collect();
    let handle = URL_SAFE_NO_PAD.encode(handle);
    let document = json!({"ceremony_id":ceremony,"publicKey":{
        "rp":{"id":rp,"name":settings.name},"user":{"id":handle,"name":handle,"displayName":"CyberdyneAuth account"},
        "challenge":URL_SAFE_NO_PAD.encode(challenge),"timeout":settings.ttl * 1000,"excludeCredentials":exclude,
        "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
        "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required"},
        "attestation":"none"
    }});
    options_response(tx, settings, binding, document).await
}

pub(super) async fn login_options(
    pool: &PgPool,
    settings: &Settings,
    rp: &str,
    binding: Transport,
) -> Result<Response, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let challenge = random_bytes();
    let ceremony = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO passkey_ceremonies
        (id,purpose,challenge,rp_id,origin,binding_hash,policy,expires_at)
        VALUES ($1,'login',$2,$3,$4,$5,$6,statement_timestamp()+$7 * interval '1 second')",
    )
    .bind(ceremony)
    .bind(challenge.as_slice())
    .bind(rp)
    .bind(&binding.origin)
    .bind(format!("{:x}", Sha256::digest(&binding.secret)))
    .bind(&settings.digest)
    .bind(settings.ttl as f64)
    .execute(&mut *tx)
    .await?;
    let document = json!({"ceremony_id":ceremony,"publicKey":{
        "rpId":rp,"timeout":settings.ttl*1000,"userVerification":"required",
        "challenge":URL_SAFE_NO_PAD.encode(challenge)
    }});
    options_response(tx, settings, binding, document).await
}

async fn options_response(
    tx: Transaction<'_, Postgres>,
    settings: &Settings,
    binding: Transport,
    mut document: Value,
) -> Result<Response, sqlx::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    if binding.native {
        document["binding_secret"] = json!(binding.secret);
    } else {
        let secure = if settings.secure { "; Secure" } else { "" };
        let cookie = format!(
            "passkey_binding={}; HttpOnly; Max-Age={}; Path=/api/v1/auth; SameSite=strict{}",
            binding_cookie::encode(&binding.secret),
            settings.ttl,
            secure
        );
        let Ok(value) = header::HeaderValue::from_str(&cookie) else {
            return Ok(problem(
                StatusCode::UNAUTHORIZED,
                "Invalid passkey ceremony or authentication proof",
            ));
        };
        headers.insert(header::SET_COOKIE, value);
    }
    tx.commit().await?;
    Ok((headers, Json(document)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn discoverable_login_persists_an_anonymous_challenge() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE passkey_ceremonies
            (id uuid PRIMARY KEY,purpose text,challenge bytea,rp_id text,origin text,
             binding_hash text,policy text,expires_at timestamptz,user_id uuid,session_id uuid,credential_id uuid)")
            .execute(&pool).await.unwrap();
        let settings = Settings {
            name: "Test".into(),
            ttl: 60,
            browser: vec![],
            native: vec![],
            digest: "policy".into(),
            dev: true,
            secure: false,
            proxy_peers: vec![],
        };
        let transport = Transport {
            origin: "https://keys.example".into(),
            secret: "test-binding".into(),
            native: true,
        };
        let response = login_options(&pool, &settings, "keys.example", transport)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let document: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["binding_secret"], "test-binding");
        let id = Uuid::parse_str(document["ceremony_id"].as_str().unwrap()).unwrap();
        let challenge=sqlx::query_scalar::<_,Vec<u8>>(
            "SELECT challenge FROM passkey_ceremonies WHERE id=$1 AND purpose='login'
             AND user_id IS NULL AND session_id IS NULL AND credential_id IS NULL
             AND expires_at>clock_timestamp() AND rp_id='keys.example' AND origin='https://keys.example'
             AND policy='policy' AND binding_hash=$2")
             .bind(id).bind(format!("{:x}",Sha256::digest("test-binding"))).fetch_one(&pool).await.unwrap();
        assert_eq!(challenge.len(), 32);
        assert_eq!(
            document["publicKey"],
            json!({"challenge":URL_SAFE_NO_PAD.encode(challenge),
            "rpId":"keys.example","timeout":60000,"userVerification":"required"})
        );
    }

    #[test]
    fn native_client_requires_an_approved_origin_and_secure_connection() {
        let origin = "https://keys.example";
        let settings = Settings {
            name: "Test".into(),
            ttl: 60,
            browser: vec![origin.into()],
            native: vec![origin.into()],
            digest: String::new(),
            dev: false,
            secure: true,
            proxy_peers: vec!["192.0.2.0/24".parse().unwrap()],
        };
        let trusted = "192.0.2.2".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("origin", origin.parse().unwrap());
        headers.insert("x-passkey-client", "native".parse().unwrap());
        assert!(settings.transport(&headers, trusted, true).is_none());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(
            settings
                .transport(&headers, "198.51.100.1".parse().unwrap(), true)
                .is_none()
        );
        assert!(settings.transport(&headers, trusted, true).is_some());
        headers.insert("cookie", "session=value".parse().unwrap());
        assert!(settings.transport(&headers, trusted, true).is_none());
        headers.remove("cookie");
        headers.insert("origin", "https://other.example".parse().unwrap());
        assert!(settings.transport(&headers, trusted, true).is_none());
    }
}
