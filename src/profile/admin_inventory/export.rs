//! Export PostgreSQL IAM state and audit the disclosure before releasing it.
use super::*;
use crate::grant_response::SessionOrigin;

pub(in crate::profile) async fn get(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    export(tx, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

#[derive(Serialize)]
struct Document {
    schema: &'static str,
    exported_at: String,
    policies: Vec<statements::ExportPolicy>,
    groups: Vec<Value>,
    roles: Vec<Value>,
    identities: Vec<Value>,
    permission_boundaries: Vec<Value>,
}

async fn export(
    mut tx: Transaction<'_, Postgres>,
    actor: (Uuid, Option<&str>),
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let policies = statements::export(&mut tx).await?;
    let groups = sqlx::query_scalar(include_str!("export/groups.sql"))
        .fetch_all(&mut *tx)
        .await?;
    let roles = sqlx::query_scalar(include_str!("export/roles.sql"))
        .fetch_all(&mut *tx)
        .await?;
    let rows = sqlx::query_as::<_, (Value, String, String, Option<Value>)>(include_str!(
        "export/identities.sql"
    ))
    .fetch_all(&mut *tx)
    .await?;
    let mut identities = Vec::with_capacity(rows.len());
    let mut permission_boundaries = Vec::new();
    for (mut identity, status, mode, boundary) in rows {
        user_identity::validate_identity(&status, &mode)?;
        identity["status"] = json!(status);
        identity["transfer_mode"] = json!(mode);
        identities.push(identity);
        permission_boundaries.extend(boundary);
    }
    let now = Utc::now();
    let precision = if now.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    let doc = Document {
        schema: "cyberdyne-iam-export/v1",
        exported_at: now.to_rfc3339_opts(precision, false),
        policies,
        groups,
        roles,
        identities,
        permission_boundaries,
    };
    crate::admin_audit::append_record(
        &mut tx,
        "iam.export",
        Some(actor),
        Some(("iam", None)),
        json!({"identities":doc.identities.len(),"policies":doc.policies.len()}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(doc).into_response())
}
