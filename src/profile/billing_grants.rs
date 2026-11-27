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
    if let Some(reference) = reference
        && !revoke(tx, reference, None, Some(source), Some(id), hooks).await?
    {
        return Ok(false);
    }
    if !hooks {
        return Ok(true);
    }
    let payload = json!({
        "product_key": product, "plan": plan, "entitlement_id": id,
        "source": source, "organization_id": null
    });
    wasm_hooks::delivery::enqueue(tx, "entitlement_granted", Some(user), payload).await
}

pub(super) async fn revoke(
    tx: &mut Transaction<'_, Postgres>,
    reference: &str,
    user: Option<Uuid>,
    source: Option<&str>,
    keep: Option<Uuid>,
    hooks: bool,
) -> sqlx::Result<bool> {
    let revoked = sqlx::query_as::<_, (Uuid, Option<Uuid>, String, Option<String>)>(
        "UPDATE entitlements SET status='revoked',revoked_at=now(),updated_at=now()
         WHERE external_ref=$1 AND status='active' AND ($2::uuid IS NULL OR user_id=$2)
         AND ($3::text IS NULL OR source=$3) AND ($4::uuid IS NULL OR id<>$4)
         RETURNING id,user_id,product_key,plan",
    )
    .bind(reference)
    .bind(user)
    .bind(source)
    .bind(keep)
    .fetch_all(&mut **tx)
    .await?;
    if hooks {
        for (id, user, product, plan) in revoked {
            if !wasm_hooks::delivery::enqueue(
                tx,
                "entitlement_revoked",
                user,
                json!({"product_key":product,"plan":plan,"entitlement_id":id}),
            )
            .await?
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
