//! Project gas estimation failures returned by Ethereum JSON-RPC providers.
use super::*;
use crate::browser_prompt::quoted_string;

pub(super) fn estimate_error(error: ReadError) -> PrepareError {
    let ReadError::Rpc(doc) = error else {
        return PrepareError::Unavailable;
    };
    let Some(reason) = reason(&doc) else {
        return PrepareError::Rpc(doc.diagnostic);
    };
    let data = match doc.data.as_deref() {
        None => quoted_string("no data"),
        Some(raw) => match crate::json_representation::representation(raw) {
            Ok(text) => text,
            Err(_) => return PrepareError::Unavailable,
        },
    };
    PrepareError::Reverted(format!("({}, {data})", quoted_string(&reason)))
}

fn reason(error: &rpc_response::RpcError) -> Option<String> {
    let message = error.message.as_str();
    match error.data.as_deref().map(|raw| raw.get()) {
        Some("null") => {
            return Some(
                if message.is_empty() {
                    "execution reverted"
                } else {
                    message
                }
                .into(),
            );
        }
        Some(raw) if raw.starts_with('{') && !message.is_empty() => {
            return Some(format!("execution reverted: {message}"));
        }
        Some(raw) if raw.starts_with('"') => {
            let data: String = serde_json::from_str(raw).ok()?;
            if data.starts_with("Reverted ") {
                return legacy_reason(&data);
            }
            if data.starts_with("0x4e487b71") {
                return panic_reason(&data);
            }
            if data.starts_with("0x") && data.len() >= 10 && !data.starts_with("0x08c379a0") {
                return Some(data);
            }
        }
        _ => {}
    }
    if error.code == Some(3) && !message.is_empty() {
        Some(message.into())
    } else {
        message
            .contains("execution reverted")
            .then(|| "execution reverted".into())
    }
}

fn legacy_reason(data: &str) -> Option<String> {
    use alloy_sol_types::SolType;
    let hex = data.strip_prefix("Reverted 0x")?;
    let bytes = HEXLOWER_PERMISSIVE.decode(hex.as_bytes()).ok()?;
    let decoded = if hex.starts_with("08c379a0") {
        <sol!(string)>::abi_decode(&bytes[4..]).ok()?
    } else {
        match String::from_utf8(bytes) {
            Ok(reason) => reason,
            Err(_) => return Some("execution reverted".into()),
        }
    };
    Some(format!("execution reverted: {decoded}"))
}

fn panic_reason(data: &str) -> Option<String> {
    let code = data.get(data.len().checked_sub(2)?..)?;
    let description = match code {
        "00" => "Generic compiler inserted panics.",
        "01" => "Assert evaluates to false.",
        "11" => "Arithmetic operation results in underflow or overflow.",
        "12" => "Division by zero.",
        "21" => "Cannot convert value into an enum type.",
        "22" => "Storage byte array is incorrectly encoded.",
        "31" => "Call to 'pop()' on an empty array.",
        "32" => "Array index is out of bounds.",
        "41" => "Allocation of too much memory or array too large.",
        "51" => "Call to a zero-initialized variable of internal function type.",
        _ => return None,
    };
    Some(format!("Panic error 0x{code}: {description}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_error_stays_distinct_from_a_contract_failure() {
        let transport = rpc_response::decode(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"node busy"}}"#,
        )
        .unwrap_err();
        assert!(matches!(
            estimate_error(transport),
            PrepareError::Rpc(text) if text == "{'code': -32000, 'message': 'node busy'}"
        ));
        let returned = rpc_response::decode(br#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted: denied","data":"0x"}}"#).unwrap_err();
        let PrepareError::Reverted(detail) = estimate_error(returned) else {
            panic!("expected contract rejection")
        };
        assert_eq!(detail, "('execution reverted: denied', '0x')");
    }
}
