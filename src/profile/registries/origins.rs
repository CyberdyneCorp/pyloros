//! Operator inventory of deployment and managed browser origins.
use super::*;
use sqlx::{Row, postgres::PgRow};
use std::collections::BTreeSet;

#[derive(Default)]
struct Flags {
    cors: bool,
    dcr_redirect: bool,
    fragment_redirect_uris: BTreeSet<String>,
}

pub(in crate::profile) fn configured() -> Result<Vec<Value>, Box<dyn Error>> {
    let mut grouped = BTreeMap::<String, Flags>::new();
    for origin in crate::cors::configured_origins()? {
        let origin = origin.trim();
        if !origin.is_empty() {
            grouped.entry(origin.into()).or_default().cors = true;
        }
    }
    for origin in crate::token_http::configured_registration_origins()? {
        grouped.entry(origin).or_default().dcr_redirect = true;
    }
    for target in crate::external_oauth::configured_redirects()? {
        let origin = crate::oauth_uri::redirect_origin(&target).unwrap_or_else(|| target.clone());
        grouped
            .entry(origin)
            .or_default()
            .fragment_redirect_uris
            .insert(target);
    }
    Ok(grouped.into_iter().map(|(origin,flags)| json!({
        "origin":origin,"id":null,"name":null,"source":"env","active":true,
        "cors":flags.cors,"dcr_redirect":flags.dcr_redirect,"fragment_redirect_uris":flags.fragment_redirect_uris,
        "created_at":null,"updated_at":null
    })).collect())
}

const SELECT: &str = "SELECT id,origin,name,cors,dcr_redirect,fragment_redirect_uris,active,created_at,updated_at FROM oauth_web_origins";
fn document(row: PgRow) -> Result<Value, sqlx::Error> {
    let redirects: BTreeSet<_> = row
        .try_get::<&str, _>("fragment_redirect_uris")?
        .split_whitespace()
        .collect();
    Ok(json!({
        "id":row.try_get::<Uuid,_>("id")?, "origin":row.try_get::<&str,_>("origin")?,
        "name":row.try_get::<Option<&str>,_>("name")?, "cors":row.try_get::<bool,_>("cors")?,
        "dcr_redirect":row.try_get::<bool,_>("dcr_redirect")?, "fragment_redirect_uris":redirects,
        "active":row.try_get::<bool,_>("active")?, "source":"admin",
        "created_at":timestamp(row.try_get("created_at")?), "updated_at":timestamp(row.try_get("updated_at")?)
    }))
}

pub(super) async fn list(
    tx: &mut Transaction<'_, Postgres>,
    configured: &[Value],
) -> Result<Response, sqlx::Error> {
    let rows = sqlx::query(SELECT)
        .try_map(document)
        .fetch_all(&mut **tx)
        .await?;
    let mut origins = configured.to_vec();
    origins.extend(rows);
    origins.sort_by(|a, b| a["origin"].as_str().cmp(&b["origin"].as_str()));
    Ok(Json(json!({"total":origins.len(),"origins":origins})).into_response())
}
pub(super) async fn get(
    tx: &mut Transaction<'_, Postgres>,
    path: &str,
) -> Result<Response, sqlx::Error> {
    let id = match crate::query::path_uuid(path, "origin_id") {
        Ok(id) => id,
        Err(issue) => return Ok(passkeys::validation(vec![issue])),
    };
    let row = sqlx::query(&format!("{SELECT} WHERE id=$1"))
        .bind(id)
        .try_map(document)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(match row {
        Some(row) => Json(row).into_response(),
        None => problem(StatusCode::NOT_FOUND, &format!("not found: {id}")),
    })
}
