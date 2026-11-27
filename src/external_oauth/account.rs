//! Resolve a provider identity inside the callback transaction.
use super::provider::Profile;
use crate::{
    key_encryption::{EncryptionError, KeyEncryptionKey},
    managed_wallet::ManagedWallet,
    profile::{enqueue_webhooks, verify_account},
};
use chrono::Utc;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub struct Account {
    pub user: Uuid,
    pub created: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("inactive account")]
    Inactive(Uuid),
    #[error("email ownership unverified")]
    UnverifiedEmail(String),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Wallet(#[from] EncryptionError),
}

type Tx<'a> = Transaction<'a, Postgres>;

/// The caller commits a successful resolution with its resulting session or CLI code.
pub async fn resolve(
    tx: &mut Tx<'_>,
    profile: &Profile,
    key: &KeyEncryptionKey,
    webhooks: bool,
) -> Result<Account, AccountError> {
    // A new subject can arrive through two distinct callback states before it has an identity row to lock.
    let identity_key = json!([profile.provider, profile.subject]).to_string();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(identity_key)
        .execute(&mut **tx)
        .await?;
    let existing = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM user_identities WHERE type='oauth' AND provider=$1 AND identifier=$2",
    )
    .bind(profile.provider)
    .bind(&profile.subject)
    .fetch_optional(&mut **tx)
    .await?;
    let account = match existing {
        Some(user) => Account {
            user,
            created: false,
        },
        None => link(tx, profile, webhooks).await?,
    };
    let (active, has_wallet) = sqlx::query_as::<_, (bool, bool)>(
        "SELECT is_active,coalesce(default_wallet_address,'')<>'' FROM users WHERE id=$1 FOR UPDATE"
    )
    .bind(account.user)
    .fetch_one(&mut **tx)
    .await?;
    if !active {
        return Err(AccountError::Inactive(account.user));
    }
    if !has_wallet {
        let wallet = ManagedWallet::generate(key)?;
        sqlx::query("UPDATE users SET default_wallet_address=$2,public_key=$3,encrypted_private_key=$4,updated_at=now() WHERE id=$1")
            .bind(account.user)
            .bind(wallet.address)
            .bind(wallet.public_key)
            .bind(wallet.encrypted_private_key)
            .execute(&mut **tx)
            .await?;
    }
    if let Some(picture) = profile.picture.as_deref().filter(|s| !s.is_empty()) {
        sqlx::query("UPDATE users SET extra_metadata=extra_metadata || jsonb_build_object('avatar_url',$2::text),updated_at=now()
            WHERE id=$1 AND extra_metadata->>'avatar_url' IS DISTINCT FROM $2")
            .bind(account.user)
            .bind(picture)
            .execute(&mut **tx)
            .await?;
    }
    Ok(account)
}

async fn by_email(
    tx: &mut Tx<'_>,
    email: Option<&str>,
) -> Result<Option<(Uuid, bool, bool)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id,is_email_verified,is_active FROM users
        WHERE id=(SELECT id FROM users WHERE lower(primary_email)=lower($1)) FOR UPDATE",
    )
    .bind(email)
    .fetch_optional(&mut **tx)
    .await
}

async fn link(tx: &mut Tx<'_>, profile: &Profile, webhooks: bool) -> Result<Account, AccountError> {
    let email = profile
        .email
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_lowercase());
    let mut matched = by_email(tx, email.as_deref()).await?;
    let mut created = false;
    if matched.is_none() {
        let new = Uuid::new_v4();
        created = sqlx::query("INSERT INTO users(id,primary_email) VALUES($1,$2) ON CONFLICT(primary_email) DO NOTHING")
            .bind(new)
            .bind(&email)
            .execute(&mut **tx)
            .await?.rows_affected() == 1;
        matched = if created {
            Some((new, false, true))
        } else {
            by_email(tx, email.as_deref()).await?
        };
    }
    let (user, verified, active) = matched.ok_or(sqlx::Error::RowNotFound)?;
    if !created && !profile.email_verified {
        return Err(AccountError::UnverifiedEmail(email.unwrap_or_default()));
    }
    if !active {
        return Err(AccountError::Inactive(user));
    }
    if profile.email_verified && !verified {
        verify_account(tx, user).await?;
        if !created {
            clear_unverified_credentials(tx, user).await?;
        }
    }
    if created && webhooks {
        enqueue_webhooks(tx, user, Utc::now()).await?;
    }
    sqlx::query("INSERT INTO user_identities(id,user_id,type,provider,identifier,extra_data) VALUES($1,$2,'oauth',$3,$4,$5)")
        .bind(Uuid::new_v4())
        .bind(user)
        .bind(profile.provider)
        .bind(&profile.subject)
        .bind(json!({"name":profile.name.as_deref().unwrap_or_default(),"picture":profile.picture.as_deref().unwrap_or_default()}))
        .execute(&mut **tx).await?;
    Ok(Account { user, created })
}

async fn clear_unverified_credentials(tx: &mut Tx<'_>, user: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET password_hash=NULL,totp_enabled=false,totp_secret_encrypted=NULL,updated_at=now() WHERE id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
