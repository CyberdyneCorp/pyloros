//! Bind a signed refresh credential to a successfully claimed user grant.
use crate::signing::SigningIdentity;
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use std::{collections::BTreeSet, net::IpAddr};
use uuid::Uuid;

use crate::{code_exchange::ClaimedGrant, grant_response::SessionOrigin};

#[derive(Clone, Copy)]
pub(crate) struct SessionRecord<'a> {
    pub user: Uuid,
    pub session: Uuid,
    pub auth_time: Option<DateTime<Utc>>,
    pub amr: Option<&'a str>,
    pub client: Option<&'a str>,
    pub scopes: Option<&'a str>,
    pub resource: Option<&'a str>,
}

pub struct GrantSessionIssuer {
    pub(crate) blockchain: std::sync::Arc<crate::chain_settings::ChainSettings>,
    signing: std::sync::Arc<SigningIdentity>,
    id_issuer: Option<String>,
    refresh_lifetime: TimeDelta,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("OIDC ID tokens require jwt_algorithm=RS256")]
    UnsupportedIdToken,
    #[error("invalid token lifetime")]
    InvalidLifetime,
    #[error("the grant resource is no longer available")]
    UnknownResource,
    #[error("token signing failed")]
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
        Self::with_identity(
            SigningIdentity::rsa(issuer, key_id, private_pem)?,
            refresh_lifetime,
        )
    }

    pub fn with_identity(
        signing: SigningIdentity,
        refresh_lifetime: TimeDelta,
    ) -> Result<Self, SessionError> {
        if refresh_lifetime.num_seconds() < 1 {
            return Err(SessionError::InvalidLifetime);
        }
        Ok(Self {
            blockchain: Default::default(),
            signing: std::sync::Arc::new(signing),
            id_issuer: None,
            refresh_lifetime,
        })
    }

    pub(crate) fn for_id_issuer(&self, issuer: &str) -> Self {
        Self {
            blockchain: self.blockchain.clone(),
            signing: self.signing.clone(),
            id_issuer: Some(issuer.to_owned()),
            refresh_lifetime: self.refresh_lifetime,
        }
    }

    pub(crate) fn id_issuer(&self) -> &str {
        self.id_issuer.as_deref().unwrap_or_else(|| self.issuer())
    }

    pub(crate) fn supports_id_tokens(&self) -> bool {
        self.signing.supports_id_tokens()
    }

    pub(crate) fn issuer(&self) -> &str {
        self.signing.issuer()
    }

    pub(crate) fn sign(&self, claims: &Value) -> Result<String, SessionError> {
        Ok(self.signing.sign(claims)?)
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
        let scopes: BTreeSet<_> = grant.scopes.split_ascii_whitespace().collect();
        let consent =
            (!scopes.is_empty()).then(|| scopes.iter().copied().collect::<Vec<_>>().join(" "));
        let record = SessionRecord {
            user: grant.user_id,
            session: claimed.session_id,
            auth_time: grant.auth_time,
            amr: grant.amr.as_deref(),
            client: Some(&grant.client_id),
            scopes: consent.as_deref(),
            resource: grant.resource.as_deref(),
        };
        let token = self
            .store_session(tx, record, SessionOrigin { user_agent, ip }, now)
            .await?;
        Ok(scopes.contains("offline_access").then_some(token))
    }

    pub(crate) fn refresh_credential(
        &self,
        user: Uuid,
        session: Uuid,
        jti: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(String, DateTime<Utc>), SessionError> {
        let expires = now
            .checked_add_signed(self.refresh_lifetime)
            .ok_or(SessionError::InvalidLifetime)?;

        let token = self.sign(&json!({
            "iss":self.issuer(),"sub":user.to_string(),"sid":session.to_string(),
            "jti":jti.to_string(),"type":"refresh","iat":now.timestamp(),"exp":expires.timestamp()
        }))?;
        Ok((token, expires))
    }

    pub(crate) async fn store_session(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        record: SessionRecord<'_>,
        origin: SessionOrigin<'_>,
        now: DateTime<Utc>,
    ) -> Result<String, SessionError> {
        let jti = Uuid::new_v4();
        let (token, expires) = self.refresh_credential(record.user, record.session, jti, now)?;
        let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
        sqlx::query(
            "INSERT INTO sessions (id,user_id,refresh_token_hash,user_agent,ip_address,
            expires_at,auth_time,amr,created_at,last_used_at)
            VALUES ($1,$2,$3,$4,$5::text::inet,$6,$7,$8,$9,$9)",
        )
        .bind(record.session)
        .bind(record.user)
        .bind(digest)
        .bind(origin.user_agent)
        .bind(origin.ip.map(|address| address.to_string()))
        .bind(expires)
        .bind(record.auth_time)
        .bind(record.amr)
        .bind(now)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "INSERT INTO refresh_tokens
            (jti,session_id,user_id,issued_at,expires_at,scopes,client_id,resource)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(jti)
        .bind(record.session)
        .bind(record.user)
        .bind(now)
        .bind(expires)
        .bind(record.scopes)
        .bind(record.client)
        .bind(record.resource)
        .execute(&mut **tx)
        .await?;
        Ok(token)
    }
}
