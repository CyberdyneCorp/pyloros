use super::*;
use axum::body::Bytes;
use axum::extract::Path;
use std::{io, path::PathBuf, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

pub(super) const MAX_EVENT: usize = 64 << 10;
pub(super) static WORKERS: Semaphore = Semaphore::const_new(2);

pub(in crate::profile) async fn dry_run(
    State(state): State<Arc<Profile>>,
    Path(digest): Path<String>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return passkeys::post_required();
    }
    let headers = req.headers().clone();
    if let Err(e) = administrator::operator(&state, &headers).await {
        return *e;
    }
    let Ok(_permit) = WORKERS.try_acquire() else {
        return crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Hook workers are busy",
        );
    };
    let event = match read_event(req).await {
        Ok(event) => event,
        Err(response) => return *response,
    };
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let result = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT component FROM pyloros_hook_artifacts WHERE sha256=$1",
    )
    .bind(digest)
    .fetch_optional(&mut *tx)
    .await;
    drop(tx);
    let component = match result {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return crate::login_http::problem(StatusCode::NOT_FOUND, "Hook artifact not found");
        }
        Err(_) => return internal(),
    };
    match timeout(Duration::from_secs(5), invoke(&component, &event)).await {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(_)) => {
            crate::login_http::problem(StatusCode::SERVICE_UNAVAILABLE, "Hook worker unavailable")
        }
        Err(_) => {
            Json(json!({"status":"failed","error":"Hook execution timed out"})).into_response()
        }
    }
}

async fn read_event(req: Request) -> Result<Bytes, Box<Response>> {
    let media = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(';').next());
    if !media.is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json")) {
        return Err(Box::new(crate::login_http::problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected application/json",
        )));
    }
    let read = to_bytes(req.into_body(), MAX_EVENT);
    let bytes = match timeout(Duration::from_secs(5), read).await {
        Err(_) => {
            return Err(Box::new(crate::login_http::problem(
                StatusCode::REQUEST_TIMEOUT,
                "Event upload timed out",
            )));
        }
        Ok(Err(e))
            if std::error::Error::source(&e)
                .is_some_and(|e| e.is::<http_body_util::LengthLimitError>()) =>
        {
            return Err(Box::new(crate::login_http::problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Hook event exceeds 64 KiB",
            )));
        }
        Ok(Err(_)) => {
            return Err(Box::new(crate::login_http::problem(
                StatusCode::BAD_REQUEST,
                "Could not read hook event",
            )));
        }
        Ok(Ok(bytes)) => bytes,
    };
    serde_json::from_slice::<Value>(&bytes).map_err(|_| {
        Box::new(crate::login_http::problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Expected a JSON event",
        ))
    })?;
    Ok(bytes)
}

pub(super) async fn invoke(component: &[u8], event: &[u8]) -> io::Result<Value> {
    let path = match std::env::var_os("PYLOROS_HOOK_WORKER") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()?.with_file_name(format!(
            "pyloros-hook-worker{}",
            std::env::consts::EXE_SUFFIX
        )),
    };
    let mut child = Command::new(path)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Missing worker input"))?;
    stdin
        .write_all(&(component.len() as u32).to_be_bytes())
        .await?;
    stdin.write_all(component).await?;
    stdin.write_all(event).await?;
    drop(stdin);
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(io::Error::other("Hook worker exited"));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
