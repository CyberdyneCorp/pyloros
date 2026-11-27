use super::*;
use crate::{grant_response::SessionOrigin, key_encryption::KeyEncryptionKey};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

pub(super) async fn rotate(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::POST {
        return passkeys::post_required();
    }
    run(&state, peer, &headers, &raw, true).await
}

pub(super) async fn remove(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    headers: HeaderMap,
) -> Response {
    run(&state, peer, &headers, &raw, false).await
}

async fn run(
    state: &Profile,
    peer: SocketAddr,
    headers: &HeaderMap,
    raw: &str,
    rotate: bool,
) -> Response {
    let (mut tx, actor, email) = match administrator::operator(state, headers).await {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let id = match crate::query::path_uuid(raw, "subscription_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(headers, "user-agent"),
    };
    let change = if rotate {
        let Some(key) = &state.registration.key else {
            return internal();
        };
        replace(&mut tx, id, key).await
    } else {
        delete(&mut tx, id).await
    };
    let change = match change {
        Ok(Some(c)) => c,
        Ok(None) => return missing(),
        Err(_) => return internal(),
    };
    if crate::admin_audit::append(
        &mut tx,
        change.action,
        Some((actor, email.as_deref())),
        ("webhook", &id.to_string()),
        change.metadata,
        origin,
    )
    .await
    .is_err()
    {
        return internal();
    }
    if tx.commit().await.is_err() {
        return internal();
    }
    change.response
}

struct Change {
    action: &'static str,
    metadata: Value,
    response: Response,
}

async fn delete(tx: &mut Tx<'_>, id: Uuid) -> sqlx::Result<Option<Change>> {
    let Some(row) = load(tx, id).await? else {
        return Ok(None);
    };
    validate_stored(&row)?;
    sqlx::query("DELETE FROM webhook_subscriptions WHERE id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(Some(Change {
        action: "webhook.delete",
        metadata: json!({"name":row.try_get::<String,_>("name")?}),
        response: StatusCode::NO_CONTENT.into_response(),
    }))
}

fn generate(key: &KeyEncryptionKey, id: Uuid) -> sqlx::Result<(String, Vec<u8>)> {
    let mut random = Zeroizing::new([0_u8; 32]);
    SystemRandom::new()
        .fill(random.as_mut())
        .map_err(|_| sqlx::Error::Protocol("cannot generate webhook secret".into()))?;
    let mut secret = String::from("whsec_");
    STANDARD.encode_string(random.as_ref(), &mut secret);
    let ciphertext = key
        .encrypt_with_aad(secret.as_bytes(), format!("webhook-secret:{id}").as_bytes())
        .map_err(|e| sqlx::Error::Encode(e.into()))?;
    Ok((secret, ciphertext))
}

async fn replace(
    tx: &mut Tx<'_>,
    id: Uuid,
    key: &KeyEncryptionKey,
) -> sqlx::Result<Option<Change>> {
    let sql = format!("SELECT {FIELDS},secret_ciphertext FROM webhook_subscriptions WHERE id=$1");
    let Some(row) = sqlx::query(&sql).bind(id).fetch_optional(&mut **tx).await? else {
        return Ok(None);
    };
    validate_stored(&row)?;
    let stored: &str = row.try_get("events")?;
    let normalized = event_types(stored, true)?;
    // Only historical non-array values are rewritten by a credential rotation.
    let normalized = (!stored.starts_with('[')).then(|| json!(normalized));
    let (secret, ciphertext) = generate(key, id)?;
    let expires = Utc::now() + chrono::Duration::hours(24);
    sqlx::query(
        "UPDATE webhook_subscriptions SET secret_ciphertext=$2,previous_secret_ciphertext=$3,
        previous_secret_expires_at=$4,event_types=COALESCE($5,event_types),updated_at=now() WHERE id=$1",
    )
    .bind(id)
    .bind(ciphertext)
    .bind(row.try_get::<&[u8], _>("secret_ciphertext")?)
    .bind(expires)
    .bind(normalized)
    .execute(&mut **tx)
    .await?;
    let current = load(tx, id).await?.ok_or(sqlx::Error::RowNotFound)?;
    let mut doc = subscription(&current, Utc::now())?;
    doc["secret"] = json!(secret);
    Ok(Some(Change {
        action: "webhook.rotate_secret",
        metadata: json!({"name":doc["name"],"secret_rotated":true}),
        response: Json(doc).into_response(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotations_generate_distinct_256_bit_keys_and_use_associated_data() {
        let key = KeyEncryptionKey::new("fixture").unwrap();
        let id = Uuid::new_v4();
        let (first, encrypted) = generate(&key, id).unwrap();
        assert_eq!(
            STANDARD
                .decode(first.strip_prefix("whsec_").unwrap())
                .unwrap()
                .len(),
            32
        );
        assert_ne!(first, generate(&key, id).unwrap().0);
        assert!(key.decrypt(&encrypted).is_err());
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn rotation_preserves_the_previous_ciphertext_and_removal_rolls_back_with_its_transaction()
     {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE webhook_subscriptions(id uuid PRIMARY KEY,name text,url text,description text,is_active bool,
            event_types jsonb,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now(),secret_ciphertext bytea,
            previous_secret_ciphertext bytea,previous_secret_expires_at timestamptz);")
            .execute(&mut *tx).await.unwrap();
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO webhook_subscriptions(id,name,url,is_active,event_types,secret_ciphertext)
            VALUES($1,'sample','https://example.test',false,'[]',$2)",
        )
        .bind(id)
        .bind(b"prior".as_slice())
        .execute(&mut *tx)
        .await
        .unwrap();
        replace(&mut tx, id, &KeyEncryptionKey::new("fixture").unwrap())
            .await
            .unwrap()
            .unwrap();
        let (old,overlap):(Vec<u8>,bool)=sqlx::query_as("SELECT previous_secret_ciphertext,
            previous_secret_expires_at BETWEEN now()+interval '23 hours 59 minutes' AND now()+interval '24 hours 1 minute'
            FROM webhook_subscriptions WHERE id=$1").bind(id).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(old, b"prior");
        assert!(overlap);
        use sqlx::Acquire;
        let mut save = tx.begin().await.unwrap();
        assert_eq!(
            delete(&mut save, id)
                .await
                .unwrap()
                .unwrap()
                .response
                .status(),
            StatusCode::NO_CONTENT
        );
        assert!(load(&mut save, id).await.unwrap().is_none());
        save.rollback().await.unwrap();
        assert!(load(&mut tx, id).await.unwrap().is_some());
    }
}
