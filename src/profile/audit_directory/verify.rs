//! Check content hashes and then walk the retained chain in linkage order.
use super::*;
use crate::admin_audit::Record;
use futures_util::TryStreamExt;
use std::collections::{HashMap, HashSet};

pub(super) async fn read(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    verify(&mut tx)
        .await
        .map(|v| Json(v).into_response())
        .unwrap_or_else(|_| internal())
}

#[derive(Serialize)]
struct Verdict {
    valid: bool,
    checked: usize,
    broken_at: Option<Uuid>,
    detail: Option<String>,
}

async fn verify(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<Verdict> {
    let mut rows = sqlx::query(
        "SELECT id,action,actor_client_id,actor_email,actor_user_id,created_at,
        host(ip_address) AS ip, masklen(ip_address) AS prefix,extra_metadata::text AS metadata,
        prev_hash,row_hash,target_id,target_type,user_agent FROM admin_action_logs",
    )
    .fetch(&mut **tx);
    let mut checked = 0;
    let mut broken_at = None;
    let mut links = HashMap::new();
    // Read all rows from one snapshot, retaining only the links needed for the walk.
    while let Some(row) = rows.try_next().await? {
        checked += 1;
        crate::stored_json::check_integers(row.try_get("metadata")?)?;
        if broken_at.is_some() {
            continue;
        }
        let hash: String = row.try_get("row_hash")?;
        if content_digest(&row)? != hash {
            broken_at = Some(row.try_get("id")?);
        } else {
            links.insert(row.try_get("prev_hash")?, hash);
        }
    }
    let detail = if broken_at.is_some() {
        Some("row content does not match its hash".into())
    } else {
        link_error(checked, &links)
    };
    Ok(Verdict {
        valid: detail.is_none(),
        checked,
        broken_at,
        detail,
    })
}

fn link_error(checked: usize, links: &HashMap<String, String>) -> Option<String> {
    if checked == 0 {
        return None;
    }
    if links.len() != checked {
        return Some("chain fork detected".into());
    }
    let produced: HashSet<_> = links.values().collect();
    let mut anchors = links.keys().filter(|prev| !produced.contains(prev));
    let first = anchors.next();
    let count = usize::from(first.is_some()) + anchors.count();
    if count != 1 {
        return Some(format!("expected one chain anchor, found {count}"));
    }
    let mut cursor = first.expect("one anchor");
    let mut walked = 0;
    while let Some(next) = links.get(cursor) {
        walked += 1;
        cursor = next;
    }
    (walked != checked).then(|| "unreachable rows (mid-chain deletion or reorder)".into())
}

fn content_digest(row: &PgRow) -> sqlx::Result<String> {
    let raw: &str = row.try_get("metadata")?;
    let object = admin_organizations::audit_object(raw)?;
    let metadata: &RawValue = serde_json::from_str(object.as_deref().unwrap_or(raw))
        .map_err(|e| sqlx::Error::Decode(e.into()))?;
    let metadata = crate::admin_audit::compact_metadata(metadata, raw.starts_with('['))
        .map_err(|e| sqlx::Error::Decode(e.into()))?;
    let ip = address(row.try_get("ip")?, row.try_get("prefix")?)?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    Record {
        action: row.try_get("action")?,
        actor_client_id: row.try_get("actor_client_id")?,
        actor_user_id: row.try_get("actor_user_id")?,
        actor_email: row.try_get("actor_email")?,
        created_at: created_at.format("%Y-%m-%dT%H:%M:%S%.6f").to_string(),
        id: row.try_get("id")?,
        ip_address: ip.as_deref(),
        metadata: &metadata,
        prev_hash: row.try_get("prev_hash")?,
        target_id: row.try_get("target_id")?,
        target_type: row.try_get("target_type")?,
        user_agent: row.try_get("user_agent")?,
    }
    .digest()
    .map_err(|e| sqlx::Error::Decode(e.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_accepts_a_retained_prefix_boundary_and_detects_an_unreachable_cycle() {
        let mut links = HashMap::from([("removed".into(), "b".into()), ("b".into(), "c".into())]);
        assert_eq!(link_error(2, &links), None);
        links.insert("x".into(), "y".into());
        links.insert("y".into(), "x".into());
        assert_eq!(
            link_error(4, &links).as_deref(),
            Some("unreachable rows (mid-chain deletion or reorder)")
        );
    }
}
