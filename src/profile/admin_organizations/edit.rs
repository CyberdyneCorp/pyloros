//! Partial directory updates and the corresponding operator audit.
use super::*;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::fields};
use serde_json::Map;

pub(in crate::profile) async fn edit(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match fields::document(&headers, &bytes) {
        Ok(body) => body,
        Err(e) => return *e,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(e) => return *e,
    };
    let Some(body) = body else { return internal() };
    let (id, patch) = match input::patch(&body, &path) {
        Ok(parsed) => parsed,
        Err(e) => return *e,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    apply(tx, id, patch, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

pub(in crate::profile) async fn deactivate(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(e) => return *e,
    };
    let id = match crate::query::path_uuid(&path, "org_id") {
        Ok(id) => id,
        Err(issue) => return passkeys::validation(vec![issue]),
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    let outcome: Result<Response, sqlx::Error> = async {
        let Some(row) = lookup(&mut tx, id).await? else {
            return Ok(problem(StatusCode::NOT_FOUND, "Organization not found"));
        };
        let mut changes = Map::new();
        if row.0["is_active"] == true {
            changes.insert("is_active".into(), Value::Bool(false));
        }
        if let Some(canonical) = metadata::normalized_storage(&row.1)? {
            changes.insert("extra_metadata".into(), Value::String(canonical));
        }
        if !changes.is_empty() {
            save(&mut tx, id, changes).await?;
        }
        crate::admin_audit::append(
            &mut tx,
            "organization.deactivate",
            Some((actor, email.as_deref())),
            ("organization", &id.to_string()),
            json!({}),
            origin,
        )
        .await?;
        tx.commit().await?;
        Ok((
            StatusCode::NO_CONTENT,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
        )
            .into_response())
    }
    .await;
    outcome.unwrap_or_else(|_| internal())
}

async fn lookup(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<DirectoryRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM organizations o WHERE id=$1"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
}

async fn apply(
    mut tx: Transaction<'_, Postgres>,
    id: Uuid,
    patch: Map<String, Value>,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let Some(row) = lookup(&mut tx, id).await? else {
        return Ok(problem(StatusCode::NOT_FOUND, "Organization not found"));
    };
    let stored_metadata = row.1.clone();
    let original = item(row)?;
    let mut desired = original.clone();
    update_fields(&mut desired, &patch);
    if let Some(domain) = desired["domain_name"].as_str().filter(|s| !s.is_empty())
        && patch.contains_key("domain_name")
        && creation::taken(&mut tx, "lower(domain_name)=$1", domain, Some(id)).await?
    {
        return Ok(problem(
            StatusCode::CONFLICT,
            &format!("Domain already in use: {domain}"),
        ));
    }
    if let Some(entries) = patch.get("metadata").and_then(Value::as_object)
        && let Err(response) = merge(&mut desired["metadata"], entries)
    {
        return Ok(*response);
    }
    if desired["is_active"] == true
        && let Some(login) = desired["github_login"].as_str().filter(|s| !s.is_empty())
        && creation::taken(
            &mut tx,
            "is_active AND lower(github_login)=$1",
            login,
            Some(id),
        )
        .await?
    {
        return Ok(problem(
            StatusCode::CONFLICT,
            &format!("GitHub login already in use: {login}"),
        ));
    }
    let mut changes = Map::new();
    for key in [
        "name",
        "short_name",
        "domain_name",
        "github_login",
        "description",
        "is_active",
    ] {
        if desired[key] != original[key] {
            changes.insert(key.into(), desired[key].clone());
        }
    }
    if patch.get("metadata").is_some_and(Value::is_object) {
        let merged = &desired["metadata"];
        let equal: bool = sqlx::query_scalar("SELECT $1::text::jsonb=$2::jsonb")
            .bind(&stored_metadata)
            .bind(merged)
            .fetch_one(&mut *tx)
            .await?;
        if !equal {
            changes.insert("extra_metadata".into(), Value::String(merged.to_string()));
        }
    } else if let Some(canonical) = metadata::normalized_storage(&stored_metadata)? {
        changes.insert("extra_metadata".into(), Value::String(canonical));
    }
    let saved = save(&mut tx, id, changes).await?;
    crate::admin_audit::append(
        &mut tx,
        "organization.update",
        Some(actor),
        ("organization", &id.to_string()),
        json!({"changed_fields":patch.keys().collect::<Vec<_>>()}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(saved).into_response())
}

fn update_fields(record: &mut Value, patch: &Map<String, Value>) {
    if let Some(name) = patch.get("name").and_then(Value::as_str) {
        record["name"] = json!(admin_fields::trimmed(name));
    }
    for key in ["short_name", "domain_name", "github_login", "description"] {
        if let Some(value) = patch.get(key) {
            let text = creation::normalized(value.as_str());
            record[key] = if key == "domain_name" {
                json!(text.map(str::to_lowercase))
            } else {
                json!(text)
            };
        }
    }
    if let Some(active) = patch.get("active").and_then(Value::as_bool) {
        record["is_active"] = json!(active);
    }
}

fn merge(current: &mut Value, edits: &Map<String, Value>) -> Result<(), Box<Response>> {
    let map = current
        .as_object_mut()
        .expect("projected directory metadata");
    for (key, value) in edits {
        if value == "" {
            map.remove(key);
        } else {
            map.insert(key.clone(), value.clone());
        }
    }
    if map.len() > 25 {
        return Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            &format!("metadata would have {} entries; max is 25", map.len()),
        )));
    }
    Ok(())
}

async fn save(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    changes: Map<String, Value>,
) -> Result<Value, sqlx::Error> {
    // Update only columns whose values differed when this request read the record.
    let row = if changes.is_empty() {
        lookup(tx, id).await?.ok_or(sqlx::Error::RowNotFound)?
    } else {
        let assignments = changes
            .keys()
            .map(|column| {
                if column == "extra_metadata" {
                    "extra_metadata=($2->>'extra_metadata')::jsonb".to_string()
                } else {
                    format!("{column}=updated.{column}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let sql=format!("UPDATE organizations AS o SET {assignments},updated_at=now()
            FROM jsonb_populate_record(NULL::organizations,$2) AS updated WHERE o.id=$1 RETURNING {COLUMNS}");
        sqlx::query_as(&sql)
            .bind(id)
            .bind(Value::Object(changes))
            .fetch_one(&mut **tx)
            .await?
    };
    item(row)
}
