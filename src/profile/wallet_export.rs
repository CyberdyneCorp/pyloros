//! Optional first-party export of the current account's custodial wallet.
use super::*;
use crate::{
    key_encryption::KeyEncryptionKey,
    login_http::problem,
    login_throttle::{LoginThrottle, RateLimited},
};

pub(super) struct Settings {
    enabled: bool,
    quota: LoginThrottle,
}

impl Settings {
    pub(super) fn configured() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            enabled: config::flag("EXPOSE_PRIVATE_KEY_ENDPOINT")?,
            quota: LoginThrottle::new(5),
        })
    }
}

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let Some(id) = administrator::identity(&state, &headers) else {
        return unauthorized();
    };
    read(&state, &id).await.unwrap_or_else(|_| internal())
}

async fn read(state: &Profile, id: &Identity) -> Result<Response, sqlx::Error> {
    if state.enforce {
        let mut tx = state.pool.begin().await?;
        // Loading the account for the revocation check also decodes its stored metadata.
        let metadata: Option<String> =
            sqlx::query_scalar("SELECT extra_metadata::text FROM users WHERE id=$1")
                .bind(id.user)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(metadata) = metadata {
            administrator::validate_metadata(&metadata)?;
        }
        if revoked(&mut tx, id).await? {
            return Ok(unauthorized());
        }
    }
    if !state.wallet_export.enabled {
        return Ok(problem(StatusCode::NOT_FOUND, "Not found"));
    }
    if !state
        .wallet_export
        .quota
        .allow_client(Some(&id.user.to_string()), None)
    {
        return Ok(RateLimited.into_response());
    }
    type Wallet = (Option<Vec<u8>>, Option<String>, String);
    let wallet: Option<Wallet> = sqlx::query_as("SELECT encrypted_private_key,default_wallet_address,extra_metadata::text FROM users WHERE id=$1")
        .bind(id.user).fetch_optional(&state.pool).await?;
    let Some((envelope, address, metadata)) = wallet else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    administrator::validate_metadata(&metadata)?;
    let (Some(envelope), Some(address)) = (envelope, address) else {
        return Ok(problem(StatusCode::NOT_FOUND, "Private key not available"));
    };
    let Some(key) = &state.registration.key else {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Wallet encryption key unavailable",
        ));
    };
    Ok(response(key, id.user, &address, &envelope))
}

fn response(key: &KeyEncryptionKey, user: Uuid, address: &str, envelope: &[u8]) -> Response {
    let Ok(plain) = key.decrypt(envelope) else {
        return internal();
    };
    #[derive(serde::Serialize)]
    struct Export<'a> {
        user_id: Uuid,
        private_key_hex: &'a str,
        address: &'a str,
    }
    let mut hex = zeroize::Zeroizing::new(String::from("0x"));
    data_encoding::HEXLOWER.encode_append(&plain, &mut hex);
    Json(Export {
        user_id: user,
        private_key_hex: &hex,
        address,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn export_preserves_leading_zeroes_and_rejects_corrupt_envelopes() {
        let user = Uuid::new_v4();
        let key = KeyEncryptionKey::new("wallet export test fixture").unwrap();
        let mut encrypted = key.encrypt(&[0, 1, 254]).unwrap();
        let ok = response(&key, user, "stored-address", &encrypted);
        let body = axum::body::to_bytes(ok.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"user_id":user,"private_key_hex":"0x0001fe","address":"stored-address"})
        );
        encrypted[0] ^= 1;
        assert_eq!(
            response(&key, user, "stored-address", &encrypted).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
