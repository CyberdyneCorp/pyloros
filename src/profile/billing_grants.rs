//! Apply a store grant while the caller holds the account lock.
use super::*;

pub(super) struct Grant<'a> {
    pub product: &'a str,
    pub plan: Option<&'a str>,
    pub expires: Option<DateTime<Utc>>,
    pub reference: Option<&'a str>,
    pub source: &'static str,
}

pub(super) async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    grant: Grant<'_>,
    hooks: bool,
) -> sqlx::Result<bool> {
    let Grant {
        product,
        plan,
        expires,
        reference,
        source,
    } = grant;
    if hooks && registration::pending_hook(tx, "entitlement_granted").await? {
        return Ok(false);
    }
    let candidates=sqlx::query_scalar::<_,Uuid>("SELECT id FROM entitlements WHERE user_id=$1 AND product_key=$2 AND plan IS NOT DISTINCT FROM $3 LIMIT 2 FOR UPDATE")
        .bind(user).bind(product).bind(plan).fetch_all(&mut **tx).await?;

    let id = match candidates.as_slice() {
        [] => sqlx::query_scalar(
            "INSERT INTO entitlements(id,user_id,product_key,plan,expires_at,source,external_ref)
            VALUES($1,$2,$3,$4,$5,$7,$6) RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(user)
        .bind(product)
        .bind(plan)
        .bind(expires)
        .bind(reference)
        .bind(source)
        .fetch_one(&mut **tx)
        .await?,
        [id] => {
            sqlx::query(
                "UPDATE entitlements SET status='active',source=$4,expires_at=$2,revoked_at=NULL,
                external_ref=coalesce($3,external_ref),updated_at=now()
                WHERE id=$1 AND (status,source,expires_at,revoked_at,external_ref) IS DISTINCT FROM
                ('active',$4::text,$2::timestamptz,NULL::timestamptz,coalesce($3,external_ref))",
            )
            .bind(id)
            .bind(expires)
            .bind(reference)
            .bind(source)
            .execute(&mut **tx)
            .await?;
            *id
        }
        _ => {
            return Err(sqlx::Error::Protocol(
                "multiple matching billing grants".into(),
            ));
        }
    };
    let superseded = sqlx::query(
        "UPDATE entitlements SET status='revoked',revoked_at=now(),updated_at=now()
        WHERE external_ref=$1 AND id<>$2 AND source=$3 AND status='active'",
    )
    .bind(reference)
    .bind(id)
    .bind(source)
    .execute(&mut **tx)
    .await?;
    let needs_dispatch = superseded.rows_affected() > 0
        && hooks
        && registration::pending_hook(tx, "entitlement_revoked").await?;
    Ok(!needs_dispatch)
}
