use super::management::{Change, commit_change};
use super::*;
use crate::grant_response::SessionOrigin;
use std::collections::HashMap;

pub(super) async fn perform(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::POST {
        return passkeys::post_required();
    }
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(a) => a,
        Err(e) => return *e,
    };
    let (field, raw) = path
        .iter()
        .next()
        .expect("one webhook action path parameter");
    let id = match crate::query::path_uuid(raw, field) {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let action = if field == "delivery_id" {
        retry(&mut tx, id).await
    } else {
        test_subscription(&mut tx, id).await
    };
    let (target, change) = match action {
        Ok(Action::Changed(id, c)) => (id, c),
        Ok(Action::Refused(response)) => return response,
        Err(_) => return internal(),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    commit_change(tx, actor, email.as_deref(), target, origin, change).await
}

enum Action {
    Changed(Uuid, Change),
    Refused(Response),
}

fn inactive() -> Action {
    Action::Refused(problem(
        StatusCode::CONFLICT,
        "Webhook subscription is inactive; activate it first",
    ))
}

async fn active(tx: &mut Tx<'_>, id: Uuid) -> sqlx::Result<Option<bool>> {
    let Some(row) = load(tx, id).await? else {
        return Ok(None);
    };
    validate_stored(&row)?;
    Ok(Some(row.try_get("is_active")?))
}

async fn test_subscription(tx: &mut Tx<'_>, id: Uuid) -> sqlx::Result<Action> {
    match active(tx, id).await? {
        None => return Ok(Action::Refused(missing())),
        Some(false) => return Ok(inactive()),
        Some(true) => {}
    }
    let event = Uuid::new_v4();
    let now = Utc::now();
    let body = registration::event_body("webhook.test", json!({"subscription_id":id}), now);
    sqlx::query(
        "INSERT INTO webhook_events(id,type,body,occurred_at) VALUES($1,'webhook.test',$2,$3)",
    )
    .bind(event)
    .bind(body)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    sqlx::query("INSERT INTO webhook_deliveries(id,event_id,subscription_id,status,attempt_count,next_attempt_at)
        VALUES(gen_random_uuid(),$1,$2,'pending',0,$3)").bind(event).bind(id).bind(now).execute(&mut **tx).await?;
    let message_id = format!("msg_{}", event.simple());
    Ok(Action::Changed(
        id,
        Change {
            action: "webhook.test",
            metadata: json!({"webhook_id":message_id}),
            response: (
                StatusCode::ACCEPTED,
                Json(json!({"webhook_id":message_id,"queued":true})),
            )
                .into_response(),
        },
    ))
}

async fn retry_record(tx: &mut Tx<'_>, id: Uuid) -> sqlx::Result<Option<(Uuid, Value)>> {
    // The retry response projects the queue row. The history endpoint separately
    // joins the event type and attempts.
    let row=sqlx::query("SELECT subscription_id,event_id,'' AS type,status,attempt_count,last_status_code,last_error,
        timestamptz_send(next_attempt_at) AS due,timestamptz_send(created_at) AS created,timestamptz_send(updated_at) AS updated
        FROM webhook_deliveries WHERE id=$1").bind(id).fetch_optional(&mut **tx).await?;
    row.map(|r| {
        Ok((
            r.try_get("subscription_id")?,
            deliveries::delivery(&r, id, Vec::new())?,
        ))
    })
    .transpose()
}

async fn retry(tx: &mut Tx<'_>, id: Uuid) -> sqlx::Result<Action> {
    let Some((subscription, record)) = retry_record(tx, id).await? else {
        return Ok(Action::Refused(problem(
            StatusCode::NOT_FOUND,
            "Webhook delivery not found",
        )));
    };
    if record["status"] == "pending" {
        return Ok(Action::Refused(problem(
            StatusCode::CONFLICT,
            "Delivery is still pending in its retry schedule",
        )));
    }
    if active(tx, subscription).await? == Some(false) {
        return Ok(inactive());
    }
    sqlx::query("UPDATE webhook_deliveries SET status='pending',attempt_count=0,next_attempt_at=$2,updated_at=now() WHERE id=$1")
        .bind(id).bind(Utc::now()).execute(&mut **tx).await?;
    let (_, record) = retry_record(tx, id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    Ok(Action::Changed(
        subscription,
        Change {
            action: "webhook.redeliver",
            metadata: json!({"delivery_id":id}),
            response: Json(record).into_response(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn test_targets_one_subscription_and_retry_preserves_the_message() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE webhook_subscriptions(id uuid PRIMARY KEY,name text,url text,is_active bool,description text,event_types jsonb,
            created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now(),previous_secret_expires_at timestamptz);
            CREATE TEMP TABLE webhook_events(id uuid PRIMARY KEY,type text,body text,occurred_at timestamptz);
            CREATE TEMP TABLE webhook_deliveries(id uuid PRIMARY KEY,event_id uuid,subscription_id uuid,status text,attempt_count int,
            next_attempt_at timestamptz,last_error text,last_status_code int,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now());
            INSERT INTO webhook_subscriptions(id,is_active,event_types) VALUES(gen_random_uuid(),true,'[]'),(gen_random_uuid(),true,'[\"webhook.test\"]');")
            .execute(&mut *tx).await.unwrap();
        let id = sqlx::query_scalar("SELECT id FROM webhook_subscriptions WHERE event_types='[]'")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let Action::Changed(_, change) = test_subscription(&mut tx, id).await.unwrap() else {
            panic!("expected queued test")
        };
        let body = axum::body::to_bytes(change.response.into_body(), 8192)
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            response,
            json!({"queued":true,"webhook_id":change.metadata["webhook_id"]})
        );
        let rows:Vec<(Uuid,Uuid,Uuid,String)>=sqlx::query_as("SELECT d.id,d.subscription_id,e.id,e.body FROM webhook_deliveries d JOIN webhook_events e ON e.id=d.event_id")
            .fetch_all(&mut *tx).await.unwrap();
        assert_eq!(rows.len(), 1);
        let (delivery, subscriber, event, body) = &rows[0];
        assert_eq!(*subscriber, id);
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap()["data"],
            json!({"subscription_id":id})
        );
        assert!(
            matches!(retry(&mut tx,*delivery).await.unwrap(),Action::Refused(r) if r.status()==StatusCode::CONFLICT)
        );
        sqlx::query(
            "UPDATE webhook_deliveries SET status='failed', attempt_count=3,last_error='timeout'",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(matches!(
            retry(&mut tx, *delivery).await.unwrap(),
            Action::Changed(_, _)
        ));
        let after:(Uuid,String,String,i32,String)=sqlx::query_as("SELECT e.id,e.body,d.status,d.attempt_count,d.last_error FROM webhook_deliveries d JOIN webhook_events e ON e.id=d.event_id")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(
            after,
            (*event, body.clone(), "pending".into(), 0, "timeout".into())
        );
    }
}
