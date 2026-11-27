//! Side-effect-free inspection of administrator-supplied WebAssembly components.
use super::*;
use axum::{body::to_bytes, extract::Request};
use ring::digest;
use tokio::sync::Semaphore;
use wasmparser::{
    Parser, Payload, PrimitiveValType, Validator,
    component_types::{ComponentDefinedType, ComponentEntityType, ComponentValType},
    types::Types,
};

const ABI: &str = "pyloros:hooks/handler@1.0.0";
const MAX_BYTES: usize = 4 * 1024 * 1024;
static VALIDATIONS: Semaphore = Semaphore::const_new(2);

pub(super) async fn validate(State(state): State<Arc<Profile>>, req: Request) -> Response {
    if req.method() != Method::POST {
        return passkeys::post_required();
    }
    match administrator::operator(&state, req.headers()).await {
        Ok(session) => drop(session),
        Err(e) => return *e,
    }
    let media = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(';').next());
    if !media.is_some_and(|s| s.trim().eq_ignore_ascii_case("application/wasm")) {
        return crate::login_http::problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected application/wasm",
        );
    }
    let Ok(permit) = VALIDATIONS.try_acquire() else {
        return crate::login_http::problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Hook validation is busy",
        );
    };
    let read = to_bytes(req.into_body(), MAX_BYTES);
    let bytes = match tokio::time::timeout(std::time::Duration::from_secs(30), read).await {
        Err(_) => {
            return crate::login_http::problem(
                StatusCode::REQUEST_TIMEOUT,
                "Hook upload timed out",
            );
        }
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error))
            if std::error::Error::source(&error)
                .is_some_and(|e| e.is::<http_body_util::LengthLimitError>()) =>
        {
            return crate::login_http::problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Hook component exceeds 4 MiB",
            );
        }
        Ok(Err(_)) => {
            return crate::login_http::problem(
                StatusCode::BAD_REQUEST,
                "Could not read the hook component",
            );
        }
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        validation_response(&bytes)
    })
    .await
    .unwrap_or_else(|_| internal())
}

fn validation_response(bytes: &[u8]) -> Response {
    if let Err(error) = inspect(bytes) {
        let body = Json(json!({"valid": false, "error": error}));
        return (StatusCode::UNPROCESSABLE_ENTITY, body).into_response();
    }
    let hash = digest::digest(&digest::SHA256, bytes);
    Json(json!({
        "valid": true,
        "abi": ABI,
        "size": bytes.len(),
        "sha256": data_encoding::HEXLOWER.encode(hash.as_ref()),
    }))
    .into_response()
}

fn inspect(bytes: &[u8]) -> Result<(), String> {
    if !Parser::is_component(bytes) {
        return Err("Expected a binary WebAssembly component".into());
    }
    let types = Validator::new()
        .validate_all(bytes)
        .map_err(|e| e.to_string())?;
    // Imports of nested modules can be satisfied inside the component.
    let mut depth = 0;
    for item in Parser::new(0).parse_all(bytes) {
        match item.map_err(|e| e.to_string())? {
            Payload::Version { .. } => depth += 1,
            Payload::End(_) => depth -= 1,
            Payload::ComponentImportSection(imports) if depth == 1 && imports.count() != 0 => {
                return Err("Hook ABI 1.0 accepts no host imports".into());
            }
            _ => (),
        }
    }
    check_handler(&types)
}

fn is_string(types: &Types, value: ComponentValType) -> bool {
    match value {
        ComponentValType::Primitive(p) => p == PrimitiveValType::String,
        ComponentValType::Type(id) => matches!(
            types[id],
            ComponentDefinedType::Primitive(PrimitiveValType::String)
        ),
    }
}

fn check_handler(types: &Types) -> Result<(), String> {
    let Some(ComponentEntityType::Instance(instance)) =
        types.component_item_for_export(ABI).map(|i| i.ty)
    else {
        return Err(format!("Expected exported interface {ABI}"));
    };
    let Some(ComponentEntityType::Func(id)) = types[instance].exports.get("handle").map(|i| i.ty)
    else {
        return Err("Expected a handle function on the hook interface".into());
    };
    let func = &types[id];
    let correct_parameter =
        matches!(&*func.params,[(name,value)] if name.as_str()=="event" && is_string(types,*value));
    let correct_result = match func.result {
        Some(ComponentValType::Type(id)) => {
            matches!(&types[id],ComponentDefinedType::Result{ok:Some(ok),err:Some(err),..} if is_string(types,*ok) && is_string(types,*err))
        }
        _ => false,
    };
    if func.async_ || !correct_parameter || !correct_result {
        return Err("Expected synchronous handle(event: string) -> result<string, string>".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
