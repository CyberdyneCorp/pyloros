//! Validate the submitted module in an isolated process without executing it.
use super::*;
use crate::request_json::{fields, token_field};
use serde_json::value::RawValue;
use std::time::Duration;
use tokio::time::timeout;

pub(in crate::profile) async fn validate_source(
    State(state): State<Arc<Profile>>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    if !matches!(
        method,
        Method::POST | Method::PUT | Method::GET | Method::DELETE
    ) {
        return passkeys::post_required();
    }
    let mut document = None;
    if matches!(method, Method::POST | Method::PUT) {
        // Allow a UTF-32 envelope containing JSON escapes around the decoded source.
        let bytes = match timeout(Duration::from_secs(30), to_bytes(body, 64 << 20)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error))
                if std::error::Error::source(&error)
                    .is_some_and(|e| e.is::<http_body_util::LengthLimitError>()) =>
            {
                return crate::login_http::problem(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Hook validation request exceeds 64 MiB",
                );
            }
            Ok(Err(_)) => return internal(),
            Err(_) => {
                return crate::login_http::problem(
                    StatusCode::REQUEST_TIMEOUT,
                    "Hook validation upload timed out",
                );
            }
        };
        document = match fields::document(&parts.headers, &bytes) {
            Ok(document) => document,
            Err(response) => return *response,
        };
    }
    if let Err(response) = administrator::operator(&state, &parts.headers).await {
        return *response;
    }
    // Other v1 methods resolve "validate" as a hook identifier.
    if method != Method::POST {
        let mut issues = vec![crate::query::path_uuid("validate", "hook_id").unwrap_err()];
        if method == Method::PUT {
            let Some(raw) = document else {
                return internal();
            };
            append_update_issues(&mut issues, &raw);
        }
        return passkeys::validation(issues);
    }
    let Some(raw) = document else {
        return internal();
    };
    let code = match fields::validate_scalar_document(&raw, &["code"], |v| {
        token_field(v, "code", 0, usize::MAX).map_err(|e| vec![e])
    }) {
        Ok(code) => code,
        Err(response) => return *response,
    };
    evaluate(&code).await
}

fn append_update_issues(issues: &mut Vec<Value>, raw: &RawValue) {
    let Ok(body) = serde_json::from_str::<Value>(raw.get()) else {
        return;
    };
    if (!body.is_object() || body.get("code").is_some_and(|v| !v.is_null()))
        && let Err(issue) = token_field(body, "code", 1, 10_000)
    {
        issues.push(issue);
    }
}

async fn evaluate(code: &str) -> Response {
    let Ok(_permit) = dry_run::WORKERS.try_acquire() else {
        return crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Hook workers are busy",
        );
    };
    let chunks = [code.as_bytes()];
    let call = dry_run::invoke_worker(Some("--parse-hook-source"), &chunks);
    match timeout(Duration::from_secs(5), call).await {
        Ok(Ok(result)) => match result["status"].as_str() {
            Some("parsed") => Json(json!({"valid":true,"error":null})).into_response(),
            Some("rejected") if result["error"].is_string() => {
                Json(json!({"valid":false,"error":result["error"]})).into_response()
            }
            Some("compiler_error") => internal(),
            _ => unavailable(),
        },
        _ => unavailable(),
    }
}

fn unavailable() -> Response {
    crate::login_http::problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Hook source validator unavailable",
    )
}
