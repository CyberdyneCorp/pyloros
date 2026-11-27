//! Run a selected component on demand without creating an automatic delivery.
use super::*;
use crate::{
    grant_response::SessionOrigin,
    login_http::problem,
    request_json::{fields, iam_document},
};
use axum::{body::Bytes, extract::Path};
use serde_json::value::RawValue;
use std::time::{Duration, Instant};
use tokio::time::timeout;

pub(in crate::profile) async fn test(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let raw = match iam_document::document(&headers, &bytes) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let (mut tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let Some(raw) = raw else { return internal() };
    let (id, context) = match input(&path, &raw) {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let selection = sqlx::query_as::<_, (i32, Option<Vec<u8>>)>(
        "SELECT h.timeout_seconds,a.component FROM hooks h LEFT JOIN pyloros_hook_bindings b ON b.hook_id=h.id
        LEFT JOIN pyloros_hook_artifacts a ON a.sha256=b.sha256 WHERE h.id=$1",
    )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await;
    let (seconds, component) = match selection {
        Ok(Some((seconds, Some(component)))) => (seconds, component),
        Ok(Some((_, None))) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hook has no selected component",
            );
        }
        Ok(None) => return problem(StatusCode::NOT_FOUND, "Hook not found"),
        Err(_) => return internal(),
    };
    let result = match execute(seconds, &component, context).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    if crate::admin_audit::append(
        &mut tx,
        "hook.test",
        Some((actor, email.as_deref())),
        ("hook", &id.to_string()),
        json!({"success":result["success"]}),
        origin,
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return internal();
    }
    Json(result).into_response()
}

fn input<'a>(path: &str, raw: &'a RawValue) -> Result<(Uuid, &'a str), Box<Response>> {
    let path_value = serde_json::value::to_raw_value(path).expect("string identifier");
    let mut issues = Vec::new();
    let id = crate::query::path_uuid(path, "hook_id")
        .map_err(|issue| issues.push((issue, &*path_value)));
    let document = fields::object_fields(raw)?;
    let mut context = "{}";
    if !raw.get().starts_with('{') {
        let body = fields::project(raw, &document, &[]);
        if let Err(issue) = admin_fields::object_field(&body) {
            issues.push((issue, raw));
        }
    } else if let Some(value) = document.get("context") {
        match value.get().as_bytes()[0] {
            b'n' => (),
            b'{' => context = value.get(),
            _ => {
                let issue = json!({"loc":["body","context"], "type":"dict_type","msg":"Input should be a valid dictionary"});
                issues.push((issue, *value));
            }
        }
    }
    if !issues.is_empty() {
        return Err(fields::invalid(issues));
    }
    Ok((id.expect("validated identifier"), context))
}

async fn execute(seconds: i32, component: &[u8], context: &str) -> Result<Value, Box<Response>> {
    let started = Instant::now();
    if !(1..=30).contains(&seconds) {
        return Err(Box::new(internal()));
    }
    let _permit = dry_run::WORKERS.try_acquire().map_err(|_| {
        Box::new(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Hook workers are busy",
        ))
    })?;
    let (output, error) = if context.len() > dry_run::MAX_EVENT {
        (None, Some("Hook event exceeds 64 KiB".to_owned()))
    } else {
        match timeout(
            Duration::from_secs(seconds as u64),
            dry_run::invoke(component, context.as_bytes()),
        )
        .await
        {
            Err(_) => (None, Some("Hook execution timed out".to_owned())),
            Ok(Err(_)) => {
                return Err(Box::new(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Hook worker unavailable",
                )));
            }
            Ok(Ok(value)) => outcome(&value).ok_or_else(|| Box::new(internal()))?,
        }
    };
    Ok(
        json!({"success":error.is_none(),"output":output,"error":error,"execution_time_ms":started.elapsed().as_millis() as u64}),
    )
}

fn outcome(value: &Value) -> Option<(Option<String>, Option<String>)> {
    match value["status"].as_str()? {
        "success" => Some((
            Some(value["output"].as_str()?)
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
            None,
        )),
        "error" => Some((None, Some(value["output"].as_str()?.to_owned()))),
        "failed" => Some((None, Some(value["error"].as_str()?.to_owned()))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_results_preserve_stdout_and_distinguish_guest_errors() {
        let success = json!({"status":"success","output":"hello\n"});
        assert_eq!(outcome(&success), Some((Some("hello\n".into()), None)));
        assert_eq!(
            outcome(&json!({"status":"success","output":""})),
            Some((None, None))
        );
        assert_eq!(
            outcome(&json!({"status":"error","output":"sample error"})),
            Some((None, Some("sample error".into())))
        );
        assert_eq!(outcome(&json!({"status":"success"})), None);
    }
}
