//! Authenticate V2 notifications before passing purchase changes to the ledger.
use super::*;
use verifier::Fault;
mod ledger;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    signed_payload: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Notice {
    #[serde(rename = "notificationUUID")]
    notification_uuid: String,
    notification_type: String,
    signed_date: i64,
    data: Option<Context>,
    summary: Option<Context>,
    external_purchase_token: Option<Context>,
    app_data: Option<Context>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Context {
    bundle_id: String,
    environment: Option<String>,
    app_apple_id: Option<u64>,
    signed_transaction_info: Option<String>,
    signed_renewal_info: Option<String>,
    external_purchase_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Renewal {
    environment: String,
    original_transaction_id: String,
    is_in_billing_retry_period: Option<bool>,
    grace_period_expires_date: Option<i64>,
}

struct Delivery {
    id: String,
    effect: Effect,
}
enum Effect {
    Ignore,
    Grant(Purchase, Option<DateTime<Utc>>),
    Revoke(Purchase),
}

impl Notice {
    fn context(&self, bundle: &str, environment: &str, app_id: Option<u64>) -> Result<(), Fault> {
        if self.notification_uuid.is_empty()
            || self.notification_uuid.len() > 128
            || self.signed_date > Utc::now().timestamp_millis() + 60000
        {
            return Err(Fault::Invalid);
        }
        let (context, actual) = match (
            &self.data,
            &self.summary,
            &self.external_purchase_token,
            &self.app_data,
        ) {
            (Some(c), None, None, None)
            | (None, Some(c), None, None)
            | (None, None, None, Some(c)) => (c, c.environment.as_deref().ok_or(Fault::Invalid)?),
            (None, None, Some(c), None) => (
                c,
                if c.external_purchase_id
                    .as_deref()
                    .is_some_and(|id| id.starts_with("SANDBOX"))
                {
                    "Sandbox"
                } else {
                    "Production"
                },
            ),
            _ => return Err(Fault::Invalid),
        };
        if context.bundle_id != bundle
            || actual != environment
            || (environment == "Production" && (app_id.is_none() || context.app_apple_id != app_id))
        {
            return Err(Fault::Invalid);
        }
        Ok(())
    }
}

async fn delivery(
    verifier: &verifier::Verifier,
    store: &Store,
    bytes: &[u8],
) -> Result<Delivery, Fault> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Fault::Invalid)?;
    let notice: Notice = verifier.decode(&envelope.signed_payload).await?;
    notice.context(&store.bundle, &store.environment, store.app_id)?;
    let effect = match notice.data {
        Some(data) => verified_effect(verifier, store, &notice.notification_type, data).await?,
        None => Effect::Ignore,
    };
    Ok(Delivery {
        id: notice.notification_uuid,
        effect,
    })
}

async fn verified_effect(
    verifier: &verifier::Verifier,
    store: &Store,
    kind: &str,
    data: Context,
) -> Result<Effect, Fault> {
    let renewal: Option<Renewal> = match data.signed_renewal_info {
        Some(value) => Some(verifier.decode(&value).await?),
        None => None,
    };
    if renewal
        .as_ref()
        .is_some_and(|r| r.environment != store.environment)
    {
        return Err(Fault::Invalid);
    }
    let Some(signed) = data.signed_transaction_info else {
        return Ok(Effect::Ignore);
    };
    let mut purchase: Purchase = verifier.decode(&signed).await?;
    if !purchase.matches(&store.bundle, &store.environment, Utc::now()) {
        return Err(Fault::Invalid);
    }
    if let Some(r) = renewal {
        if r.original_transaction_id != purchase.original_transaction_id {
            return Err(Fault::Invalid);
        }
        if r.is_in_billing_retry_period == Some(true) {
            purchase.expires_date = purchase.expires_date.max(r.grace_period_expires_date);
        }
    }
    match kind {
        "SUBSCRIBED" | "DID_RENEW" | "DID_CHANGE_RENEWAL_STATUS" | "DID_FAIL_TO_RENEW" => {
            if purchase.revocation_date.is_some()
                || purchase
                    .expires_date
                    .is_some_and(|t| t <= Utc::now().timestamp_millis())
            {
                return Ok(Effect::Ignore);
            }
            let expiry = purchase.expiry(&store.bundle, &store.environment, Utc::now())?;
            Ok(Effect::Grant(purchase, expiry))
        }
        "EXPIRED" | "GRACE_PERIOD_EXPIRED" | "REVOKE" | "REFUND" => Ok(Effect::Revoke(purchase)),
        _ => Ok(Effect::Ignore),
    }
}
pub(in crate::profile) async fn handle(
    State(state): State<Arc<Profile>>,
    method: Method,
    bytes: Bytes,
) -> Response {
    if method != Method::POST {
        return passkeys::post_required();
    }
    let Some(store) = &state.apple else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"billing not enabled"})),
        )
            .into_response();
    };
    let Ok(verifier) = store.verifier().await else {
        return internal();
    };
    let delivery = match delivery(verifier, store, &bytes).await {
        Ok(value) => value,
        Err(Fault::Invalid) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid signature"})),
            )
                .into_response();
        }
        Err(Fault::Unavailable) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    match ledger::process(&state.pool, delivery, state.registration.hooks).await {
        Ok(Some(handled)) => Json(json!({"received":true,"handled":handled})).into_response(),
        Ok(None) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(_) => internal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(field: &str, data: Value) -> Notice {
        serde_json::from_value(json!({"notificationUUID":"message","notificationType":"TEST","signedDate":1,field:data})).unwrap()
    }

    #[test]
    fn production_requires_the_configured_store_application() {
        let app = json!({"bundleId":"test.bundle","environment":"Production","appAppleId":123});
        for field in ["data", "summary", "appData"] {
            let notice = context(field, app.clone());
            assert!(
                notice
                    .context("test.bundle", "Production", Some(123))
                    .is_ok()
            );
            assert!(
                notice
                    .context("test.bundle", "Production", Some(456))
                    .is_err()
            );
            assert!(notice.context("test.bundle", "Sandbox", Some(123)).is_err());
        }
        let external = context(
            "externalPurchaseToken",
            json!({"bundleId":"test.bundle","externalPurchaseId":"SANDBOX-token"}),
        );
        assert!(external.context("test.bundle", "Sandbox", None).is_ok());
        let mixed = context(
            "data",
            json!({"bundleId":"test.bundle","environment":"Production","externalPurchaseId":"SANDBOX-token"}),
        );
        assert!(mixed.context("test.bundle", "Sandbox", None).is_err());
    }
}
