//! Issue a fresh sign-in message and retain its exact bytes for verification.
use super::super::*;
use crate::{
    login_throttle::{LoginThrottle, RateLimited},
    request_json::{fields, iam_document},
};
use chrono::{Datelike, TimeDelta, Timelike};
use data_encoding::HEXLOWER;
use rand::{RngCore, rngs::OsRng};
use serde_json::value::RawValue;

pub(in crate::profile) struct Settings {
    domain: String,
    ttl: i64,
    quota: LoginThrottle,
}

impl Settings {
    pub(in crate::profile) fn configured() -> Result<Self, std::num::ParseIntError> {
        Ok(Self {
            domain: env::var("WALLET_AUTH_DOMAIN").unwrap_or_else(|_| "cyberdyne.local".into()),
            ttl: env::var("WALLET_CHALLENGE_TTL_SECONDS").map_or(Ok(300), |v| v.parse())?,
            quota: LoginThrottle::new(
                env::var("RATELIMIT_WALLET_PER_MIN").map_or(Ok(10), |v| v.parse())?,
            ),
        })
    }
}

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let raw = match iam_document::document(&headers, &bytes) {
        Ok(Some(raw)) => raw,
        Ok(None) => return internal(),
        Err(r) => return *r,
    };
    let (address, chain) = match input(&raw) {
        Ok(pair) => pair,
        Err(r) => return *r,
    };
    let settings = &state.wallet_challenges;
    if !settings.quota.allow(crate::token_http::client_ip(
        &headers,
        peer.ip(),
        state.proxies,
    )) {
        return RateLimited.into_response();
    }
    let Ok(chain) = chain.parse::<i32>() else {
        return internal();
    };
    store(&state.pool, settings, &address, chain)
        .await
        .unwrap_or_else(|_| internal())
}

fn wallet_address<'a>(
    submitted: &std::collections::HashMap<String, &'a RawValue>,
    raw: &'a RawValue,
) -> Result<String, (Value, &'a RawValue)> {
    let location = ["body", "wallet_address"];
    let Some(&value) = submitted.get("wallet_address") else {
        return Err((
            json!({"type":"missing","loc":location,"msg":"Field required"}),
            raw,
        ));
    };
    let address = serde_json::from_str::<String>(value.get()).map_err(|_| {
        (
            json!({"type":"string_type","loc":location,"msg":"Input should be a valid string"}),
            value,
        )
    })?;
    let valid = address
        .strip_prefix("0x")
        .is_some_and(|digits| digits.len() == 40 && digits.bytes().all(|c| c.is_ascii_hexdigit()));
    if valid {
        return Ok(address);
    }
    let reason = "wallet_address must be a 0x-prefixed 40-hex-char EVM address";
    Err((
        json!({"type":"value_error","loc":location,"msg":format!("Value error, {reason}"),"ctx":{"error":reason}}),
        value,
    ))
}

fn input(raw: &RawValue) -> Result<(String, String), Box<Response>> {
    let submitted = fields::object_fields(raw)?;
    if !raw.get().starts_with('{') {
        let issue = admin_fields::object_field(&fields::project(raw, &submitted, &[])).unwrap_err();
        return Err(fields::invalid(vec![(issue, raw)]));
    }
    let mut issues = Vec::new();
    let address = wallet_address(&submitted, raw)
        .map_err(|issue| issues.push(issue))
        .ok();
    let chain = match submitted
        .get("chain_id")
        .map(|raw| fields::integer_text(raw))
        .transpose()
    {
        Ok(chain) => chain.unwrap_or_else(|| "1".into()),
        Err((kind, message)) => {
            issues.push((
                json!({"type":kind,"loc":["body","chain_id"],"msg":message}),
                submitted["chain_id"],
            ));
            String::new()
        }
    };
    if !issues.is_empty() {
        return Err(fields::invalid(issues));
    }
    Ok((address.expect("validated wallet address"), chain))
}

fn timestamp(time: DateTime<Utc>) -> String {
    let precision = if time.nanosecond() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    time.to_rfc3339_opts(precision, false)
}

async fn store(
    pool: &PgPool,
    settings: &Settings,
    address: &str,
    chain: i32,
) -> Result<Response, sqlx::Error> {
    let id = Uuid::new_v4();
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let nonce = HEXLOWER.encode(&random);
    let issued = DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("current UTC timestamp");
    let expires = TimeDelta::try_seconds(settings.ttl)
        .and_then(|delta| issued.checked_add_signed(delta))
        .filter(|t| (1..=9999).contains(&t.year()))
        .ok_or_else(|| sqlx::Error::Protocol("challenge expiry out of range".into()))?;
    let domain = &settings.domain;
    let message = format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\nAuthenticate with CyberdyneAuth.\nURI: https://{domain}\nVersion: 1\nChain ID: {chain}\nNonce: {nonce}\nIssued At: {}\nExpiration Time: {}\n",
        timestamp(issued),
        timestamp(expires)
    );
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO auth_challenges(id,wallet_address,chain_id,nonce,status,extra_metadata,expires_at)
        VALUES($1,$2,$3,$4,'pending',$5,$6)")
        .bind(id)
        .bind(address.to_ascii_lowercase())
        .bind(chain)
        .bind(&nonce)
        .bind(json!({"message":message}))
        .bind(expires)
        .execute(&mut *tx)
        .await?;
    if tx.commit().await.is_err() {
        eprintln!("could not commit issued wallet challenge");
    }
    let response = json!({
        "challenge_id": id,
        "message": message,
        "nonce": nonce,
        "expires_in_seconds": settings.ttl,
    });
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn issued_message_and_expiration_survive_database_handoff() -> Result<(), sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await?;
        sqlx::raw_sql("CREATE TEMP TABLE auth_challenges(id uuid PRIMARY KEY, wallet_address text,
            chain_id int, nonce text UNIQUE, status text, extra_metadata jsonb, expires_at timestamptz)")
            .execute(&pool).await?;
        let settings = Settings {
            domain: "wallet.example".into(),
            ttl: 27,
            quota: LoginThrottle::new(5),
        };
        let address = "0xAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAb";
        let response = store(&pool, &settings, address, 17).await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let id: Uuid = serde_json::from_value(body["challenge_id"].clone()).unwrap();
        let (saved, nonce, message, expiry) = sqlx::query_as::<
            _,
            (String, String, String, DateTime<Utc>),
        >(
            "SELECT wallet_address,nonce,extra_metadata->>'message',expires_at FROM auth_challenges
             WHERE id=$1 AND status='pending' AND chain_id=17",
        )
        .bind(id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(saved, address.to_ascii_lowercase());
        assert_eq!(body["message"], message);
        assert_eq!(body["nonce"], nonce);
        assert_eq!(body["expires_in_seconds"], 27);
        assert_eq!(HEXLOWER.decode(nonce.as_bytes()).unwrap().len(), 16);
        assert!(message.contains(&format!("\n{address}\n")));
        let issued = expiry - TimeDelta::seconds(27);
        assert!(message.ends_with(&format!(
            "Nonce: {nonce}\nIssued At: {}\nExpiration Time: {}\n",
            timestamp(issued),
            timestamp(expiry)
        )));
        Ok(())
    }
}
