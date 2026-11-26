//! Bind a signed refresh credential to a successfully claimed user grant.
use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use std::{collections::BTreeSet, net::IpAddr};
use uuid::Uuid;

use crate::code_exchange::ClaimedGrant;

pub struct GrantSessionIssuer {
    key: EncodingKey,
    header: Header,
    issuer: String,
    refresh_lifetime: TimeDelta,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("invalid refresh token lifetime")]
    InvalidLifetime,
    #[error("refresh token signing failed")]
    Signing(#[from] jsonwebtoken::errors::Error),
    #[error("session persistence failed")]
    Storage(#[from] sqlx::Error),
}

impl GrantSessionIssuer {
    pub fn new(
        issuer: String,
        key_id: String,
        private_pem: &[u8],
        refresh_lifetime: TimeDelta,
    ) -> Result<Self, SessionError> {
        if refresh_lifetime.num_seconds() < 1 {
            return Err(SessionError::InvalidLifetime);
        }
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_id);
        Ok(Self {
            key: EncodingKey::from_rsa_pem(private_pem)?,
            header,
            issuer,
            refresh_lifetime,
        })
    }

    /// Call in the same transaction as redemption. Release the returned credential only after commit.
    pub async fn create(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        claimed: &ClaimedGrant,
        now: DateTime<Utc>,
        user_agent: Option<&str>,
        ip: Option<IpAddr>,
    ) -> Result<Option<String>, SessionError> {
        let grant = &claimed.grant;
        let expires = now
            .checked_add_signed(self.refresh_lifetime)
            .ok_or(SessionError::InvalidLifetime)?;
        let jti = Uuid::new_v4();
        let token = encode(
            &self.header,
            &json!({
                "iss":self.issuer,"sub":grant.user_id.to_string(),"sid":claimed.session_id.to_string(),
                "jti":jti.to_string(),"type":"refresh","iat":now.timestamp(),"exp":expires.timestamp()
            }),
            &self.key,
        )?;
        let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
        sqlx::query(
            "INSERT INTO sessions (id,user_id,refresh_token_hash,user_agent,ip_address,
            expires_at,auth_time,amr,created_at,last_used_at)
            VALUES ($1,$2,$3,$4,$5::text::inet,$6,$7,$8,$9,$9)",
        )
        .bind(claimed.session_id)
        .bind(grant.user_id)
        .bind(digest)
        .bind(user_agent)
        .bind(ip.map(|address| address.to_string()))
        .bind(expires)
        .bind(grant.auth_time)
        .bind(&grant.amr)
        .bind(now)
        .execute(&mut **tx)
        .await?;
        let scopes: BTreeSet<_> = grant.scopes.split_ascii_whitespace().collect();
        let consent =
            (!scopes.is_empty()).then(|| scopes.iter().copied().collect::<Vec<_>>().join(" "));
        sqlx::query(
            "INSERT INTO refresh_tokens
            (jti,session_id,user_id,issued_at,expires_at,scopes,client_id,resource)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(jti)
        .bind(claimed.session_id)
        .bind(grant.user_id)
        .bind(now)
        .bind(expires)
        .bind(consent)
        .bind(&grant.client_id)
        .bind(&grant.resource)
        .execute(&mut **tx)
        .await?;
        Ok(scopes.contains("offline_access").then_some(token))
    }
}
