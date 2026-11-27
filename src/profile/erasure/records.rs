use super::*;

// Only these owned collections contribute cascade counts to the REST report.
const OWNED: &[&str] = &[
    "user_identities",
    "user_organizations",
    "sessions",
    "refresh_tokens",
    "email_verification_tokens",
    "password_reset_tokens",
    "cli_login_codes",
    "oauth_consents",
    "oidc_authorization_codes",
    "device_authorizations",
    "mfa_recovery_codes",
    "magic_link_challenges",
    "passkey_handles",
    "passkeys",
    "passkey_ceremonies",
    "passkey_reauthentication",
    "entitlements",
    "stripe_customers",
    "apple_transactions",
    "google_purchases",
];
pub(super) async fn remove_direct_relationships(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> sqlx::Result<i64> {
    let installed: bool =
        sqlx::query_scalar("SELECT to_regclass('pyloros_user_relationships') IS NOT NULL")
            .fetch_one(&mut **tx)
            .await?;
    if !installed {
        return Ok(0);
    }
    // Order grants (which take a foreign-key lock) before or after this erasure.
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    let deleted = sqlx::query("DELETE FROM pyloros_user_relationships WHERE user_id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    Ok(deleted.rows_affected() as i64)
}

pub(super) async fn erase(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    ids: &Identifiers,
) -> Result<Counts, sqlx::Error> {
    let mut counts = Counts::default();
    let accounts = sqlx::query_scalar("SELECT count(*) FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
    counts.deleted("users", accounts);
    for &table in OWNED {
        let sql = format!("SELECT count(*) FROM {table} WHERE user_id=$1");
        let n = sqlx::query_scalar(&sql)
            .bind(user)
            .fetch_one(&mut **tx)
            .await?;
        counts.deleted(table, n);
    }
    let wallets: Vec<_> = ids.wallets.iter().collect();
    let n = sqlx::query(
        "DELETE FROM auth_challenges WHERE user_id=$1 OR lower(wallet_address)=ANY($2)",
    )
    .bind(user)
    .bind(&wallets)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    counts.deleted("auth_challenges", n as i64);
    let n = sqlx::query("DELETE FROM phone_otps WHERE phone_number=ANY($1)")
        .bind(ids.phones.iter().collect::<Vec<_>>())
        .execute(&mut **tx)
        .await?
        .rows_affected();
    counts.deleted("phone_otps", n as i64);
    let n = sqlx::query(
        "UPDATE iam_identities SET email=NULL,owner_address=NULL,public_key=NULL
        WHERE user_id=$1 OR lower(email)=ANY($2) OR lower(owner_address)=ANY($3)",
    )
    .bind(user)
    .bind(ids.emails.iter().collect::<Vec<_>>())
    .bind(wallets)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    counts.rewritten("iam_identities", n as i64);
    counts.rewritten("auth_events", activity::rewrite(tx, user, ids).await?);
    for table in [
        "passkey_reauthentication",
        "passkey_ceremonies",
        "passkeys",
        "passkey_handles",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id=$1"))
            .bind(user)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    // The user cascade waits for any worker holding an older personal delivery.
    let n = sqlx::query("DELETE FROM hook_executions WHERE user_id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    counts.deleted("hook_executions", n as i64);
    Ok(counts)
}
