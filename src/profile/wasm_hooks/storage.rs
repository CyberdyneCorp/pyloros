use super::*;
use axum::extract::Path;

pub(in crate::profile) async fn install(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let headers = req.headers().clone();
    let artifact = match upload(&state, req).await {
        Ok(artifact) => artifact,
        Err(response) => return *response,
    };
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let inserted = sqlx::query(
        "INSERT INTO pyloros_hook_artifacts (sha256, component, abi, installed_by)
         VALUES ($1, $2, $3, $4) ON CONFLICT (sha256) DO NOTHING",
    )
    .bind(&artifact.digest)
    .bind(artifact.bytes.as_ref())
    .bind(ABI)
    .bind(actor)
    .execute(&mut *tx)
    .await;
    let Ok(result) = inserted else {
        return internal();
    };
    let status = if result.rows_affected() == 1 {
        let origin = crate::grant_response::SessionOrigin {
            ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
            user_agent: crate::token_http::header(&headers, "user-agent"),
        };
        if crate::admin_audit::append(
            &mut tx,
            "hook.artifact.install",
            Some((actor, email.as_deref())),
            ("hook_artifact", &artifact.digest),
            json!({"abi": ABI, "size": artifact.bytes.len()}),
            origin,
        )
        .await
        .is_err()
        {
            return internal();
        }
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    if tx.commit().await.is_err() {
        return internal();
    }
    (status, artifact.metadata()).into_response()
}

pub(in crate::profile) async fn download(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    Path(digest): Path<String>,
) -> Response {
    let mut tx = match administrator::read(&state, method, &headers).await {
        Ok(tx) => tx,
        Err(response) => return *response,
    };
    let bytes = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT component FROM pyloros_hook_artifacts WHERE sha256=$1",
    )
    .bind(digest)
    .fetch_optional(&mut *tx)
    .await;
    match bytes {
        Ok(Some(bytes)) => ([(header::CONTENT_TYPE, "application/wasm")], bytes).into_response(),
        Ok(None) => crate::login_http::problem(StatusCode::NOT_FOUND, "Hook artifact not found"),
        Err(_) => internal(),
    }
}
