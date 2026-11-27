use super::*;
use sqlx::{Row, postgres::PgRow};

const MEMBER_IDS: &str = "SELECT user_id FROM entitlements WHERE product_key=$1 AND status='active'
    UNION SELECT user_id FROM oidc_authorization_codes WHERE client_id=$1 AND consumed_at IS NOT NULL";

struct Grant {
    plan: Option<String>,
    source: Option<String>,
}

async fn grants(
    tx: &mut Tx<'_>,
    users: &[Uuid],
    projects: &[String],
) -> sqlx::Result<HashMap<(Uuid, String), Grant>> {
    let rows = sqlx::query("SELECT DISTINCT ON (user_id,product_key) user_id,product_key,plan,source FROM entitlements
        WHERE status='active' AND user_id=ANY($1) AND product_key=ANY($2) ORDER BY user_id,product_key,created_at DESC")
        .bind(users).bind(projects).fetch_all(&mut **tx).await?;
    rows.into_iter()
        .map(|row| {
            Ok((
                (row.try_get("user_id")?, row.try_get("product_key")?),
                Grant {
                    plan: row.try_get("plan")?,
                    source: row.try_get("source")?,
                },
            ))
        })
        .collect()
}

fn usage(grant: Option<&Grant>, activity: Option<&PgRow>) -> sqlx::Result<Value> {
    let (count, last) = match activity {
        Some(row) => (
            row.try_get::<i64, _>("n")?,
            Some(stamp(row.try_get("last")?)?),
        ),
        None => (0, None),
    };
    Ok(
        json!({"entitlement_status":grant.map(|_| "active"), "source":grant.and_then(|g| g.source.as_ref()),
        "plan":grant.and_then(|g| g.plan.as_ref()), "login_count":count,"last_login":last}),
    )
}

pub(super) async fn members(tx: &mut Tx<'_>, client: &str, page: Page) -> sqlx::Result<Response> {
    if !registry::exists(tx, client).await? {
        return Ok(problem(StatusCode::NOT_FOUND, "Project not found"));
    }
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM ({MEMBER_IDS}) members"))
        .bind(client)
        .fetch_one(&mut **tx)
        .await?;
    let ids: Vec<Uuid> =
        sqlx::query_scalar(&format!("{MEMBER_IDS} ORDER BY user_id LIMIT $2 OFFSET $3"))
            .bind(client)
            .bind(page.size)
            .bind(page.offset()?)
            .fetch_all(&mut **tx)
            .await?;
    let users = if ids.is_empty() {
        Vec::new()
    } else {
        member_details(tx, client, &ids).await?
    };
    Ok(Json(json!({"client_id":client,"users":users,"total":total,"page":page.number,"page_size":page.size})).into_response())
}

async fn member_details(tx: &mut Tx<'_>, client: &str, ids: &[Uuid]) -> sqlx::Result<Vec<Value>> {
    let emails: HashMap<Uuid, Option<String>> =
        sqlx::query_as("SELECT id,primary_email FROM users WHERE id=ANY($1)")
            .bind(ids)
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .collect();
    let key = client.to_owned();
    let grants = grants(tx, ids, std::slice::from_ref(&key)).await?;
    let activity = sqlx::query("SELECT user_id,count(*) AS n,timestamptz_send(max(consumed_at)) AS last FROM oidc_authorization_codes
        WHERE client_id=$1 AND user_id=ANY($2) AND consumed_at IS NOT NULL GROUP BY user_id")
        .bind(client).bind(ids).fetch_all(&mut **tx).await?.into_iter()
        .map(|r| Ok((r.try_get::<Uuid,_>("user_id")?,r))).collect::<sqlx::Result<HashMap<_,_>>>()?;
    ids.iter()
        .map(|id| {
            let mut item = usage(grants.get(&(*id, key.clone())), activity.get(id))?;
            item["user_id"] = json!(id);
            item["email"] = json!(emails.get(id));
            Ok(item)
        })
        .collect()
}

pub(super) async fn projects(tx: &mut Tx<'_>, user: Uuid) -> sqlx::Result<Response> {
    let row: Option<(String, Vec<Vec<u8>>)> = sqlx::query_as("SELECT extra_metadata::text,
        ARRAY_REMOVE(ARRAY[timestamptz_send(created_at),timestamptz_send(updated_at),timestamptz_send(tokens_valid_after),
            timestamptz_send(last_magic_link_at)],NULL) FROM users WHERE id=$1")
        .bind(user).fetch_optional(&mut **tx).await?;
    let Some((metadata, times)) = row else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    administrator::validate_metadata(&metadata)?;
    for time in times {
        event_time::EventTime::decode(&time)?;
    }
    let ids: Vec<String> = sqlx::query_scalar("SELECT product_key FROM entitlements WHERE user_id=$1 AND status='active'
        UNION SELECT client_id FROM oidc_authorization_codes WHERE user_id=$1 AND consumed_at IS NOT NULL")
        .bind(user).fetch_all(&mut **tx).await?;
    let projects = if ids.is_empty() {
        Vec::new()
    } else {
        project_details(tx, user, &ids).await?
    };
    Ok(Json(json!({"user_id":user,"projects":projects})).into_response())
}

async fn project_details(tx: &mut Tx<'_>, user: Uuid, ids: &[String]) -> sqlx::Result<Vec<Value>> {
    let names: HashMap<String, String> =
        sqlx::query_as("SELECT client_id,name FROM oauth_clients WHERE client_id=ANY($1)")
            .bind(ids)
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .collect();
    let grants = grants(tx, &[user], ids).await?;
    let activity = sqlx::query("SELECT client_id,count(*) AS n,timestamptz_send(max(consumed_at)) AS last,timestamptz_send(min(created_at)) AS first
        FROM oidc_authorization_codes WHERE user_id=$1 AND client_id=ANY($2) AND consumed_at IS NOT NULL GROUP BY client_id")
        .bind(user).bind(ids).fetch_all(&mut **tx).await?.into_iter()
        .map(|r| Ok((r.try_get::<String,_>("client_id")?,r))).collect::<sqlx::Result<HashMap<_,_>>>()?;
    let mut ordered = ids.to_vec();
    ordered.sort_by_cached_key(|id| (names.get(id).unwrap_or(id).to_lowercase(), id.clone()));
    ordered
        .into_iter()
        .map(|id| {
            let row = activity.get(&id);
            let mut item = usage(grants.get(&(user, id.clone())), row)?;
            item["client_id"] = json!(id);
            item["name"] = json!(names.get(&id).unwrap_or(&id));
            item["first_seen"] = json!(row.map(|r| stamp(r.try_get("first")?)).transpose()?);
            Ok(item)
        })
        .collect()
}
