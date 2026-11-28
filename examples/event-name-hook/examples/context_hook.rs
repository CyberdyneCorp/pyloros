//! Display the caller's ordered context with the original literal formatting.
#[path = "../src/float_literal.rs"]
mod float_literal;
#[path = "../../../shared/string_literal.rs"]
mod string_literal;

use indexmap::IndexMap;
use serde_json::value::RawValue;
use string_literal::quoted_string;

wit_bindgen::generate!({
    path: "../../wit",
    world: "hook",
});

struct ContextHook;

#[derive(serde::Deserialize, Eq, Hash, PartialEq)]
struct FieldName<'a>(#[serde(borrow)] std::borrow::Cow<'a, str>);

const OUTPUT_LIMIT: usize = 10_000;

#[derive(Default)]
struct DisplayOutput {
    text: String,
    chars: usize,
}

impl DisplayOutput {
    fn push_ascii(&mut self, value: &str) {
        let end = value.len().min(OUTPUT_LIMIT - self.chars);
        self.text.push_str(&value[..end]);
        self.chars += end;
    }

    fn push(&mut self, value: &str) {
        let space = OUTPUT_LIMIT - self.chars;
        if value.len() <= space {
            self.text.push_str(value);
            self.chars += value.chars().count();
        } else if let Some((end, _)) = value.char_indices().nth(space) {
            self.text.push_str(&value[..end]);
            self.chars = OUTPUT_LIMIT;
        } else {
            self.text.push_str(value);
            self.chars += value.chars().count();
        }
    }
}

fn object(text: &str, out: &mut DisplayOutput) -> Result<(), String> {
    if text == "{}" {
        out.push_ascii("{}");
        return Ok(());
    }
    let fields: IndexMap<FieldName<'_>, &RawValue> =
        serde_json::from_str(text).map_err(|e| e.to_string())?;
    out.push_ascii("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if out.chars == OUTPUT_LIMIT {
            break;
        }
        if index > 0 {
            out.push_ascii(", ");
        }
        if key
            .0
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) && !matches!(b, b'\'' | b'\\'))
        {
            out.push_ascii("'");
            out.push(&key.0);
            out.push_ascii("'");
        } else {
            out.push(&quoted_string(&key.0));
        }
        out.push_ascii(": ");
        render(value, out)?;
    }
    out.push_ascii("}");
    Ok(())
}

fn array(text: &str, out: &mut DisplayOutput) -> Result<(), String> {
    // The enclosing RawValue has already validated the complete array. Nested
    // arrays can share a cursor; only objects need a member index for duplicate keys.
    let mut rest = text;
    while !rest.is_empty() && out.chars < OUTPUT_LIMIT {
        let byte = rest.as_bytes()[0];
        let consumed = match byte {
            b'[' => {
                out.push_ascii("[");
                1
            }
            b']' => {
                out.push_ascii("]");
                1
            }
            b',' => {
                out.push_ascii(", ");
                1
            }
            b if b.is_ascii_whitespace() => 1,
            b'"' => render_array_string(rest, out)?,
            b'{' => {
                let mut values = serde_json::Deserializer::from_str(rest).into_iter::<&RawValue>();
                let value = values
                    .next()
                    .expect("validated array member")
                    .map_err(|e| e.to_string())?;
                render(value, out)?;
                values.byte_offset()
            }
            _ => {
                let end = rest
                    .bytes()
                    .position(|b| matches!(b, b',' | b']') || b.is_ascii_whitespace())
                    .unwrap_or(rest.len());
                scalar(&rest[..end], out)?;
                end
            }
        };
        rest = &rest[consumed..];
    }
    Ok(())
}

fn render_array_string(text: &str, out: &mut DisplayOutput) -> Result<usize, String> {
    let content = &text[1..];
    let end = content
        .bytes()
        .position(|b| matches!(b, b'"' | b'\\' | b'\'') || !b.is_ascii_graphic() && b != b' ')
        .expect("validated JSON string ends with a quote");
    if content.as_bytes()[end] == b'"' {
        out.push_ascii("'");
        out.push_ascii(&content[..end]);
        out.push_ascii("'");
        return Ok(end + 2);
    }
    let mut values = serde_json::Deserializer::from_str(text).into_iter::<String>();
    let decoded = values
        .next()
        .expect("validated string")
        .map_err(|e| e.to_string())?;
    out.push(&quoted_string(&decoded));
    Ok(values.byte_offset())
}

fn render(raw: &RawValue, out: &mut DisplayOutput) -> Result<(), String> {
    let text = raw.get();
    match text.as_bytes()[0] {
        b'{' => return object(text, out),
        b'[' => return array(text, out),
        b'"' => {
            let s: String = serde_json::from_str(text).map_err(|e| e.to_string())?;
            out.push(&quoted_string(&s));
        }
        _ => return scalar(text, out),
    }
    Ok(())
}

// A fixed-point decimal with at most 12 digits has much wider spacing
// than binary64 rounding error. Its shortest fixed-point spelling keeps
// exactly these significant digits. Delegate exponents and longer inputs
// to the round-trip formatter.
fn short_decimal(text: &str) -> Option<&str> {
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (whole, fraction) = unsigned.split_once('.')?;
    if unsigned.len() > 13 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = text.trim_end_matches('0');
    if trimmed.ends_with('.') {
        return Some(&text[..trimmed.len() + 1]);
    }
    if whole == "0" && fraction.starts_with("0000") {
        return None;
    }
    Some(trimmed)
}

fn scalar(text: &str, out: &mut DisplayOutput) -> Result<(), String> {
    match text.as_bytes()[0] {
        b'n' => out.push_ascii("None"),
        b't' => out.push_ascii("True"),
        b'f' => out.push_ascii("False"),
        _ if text.bytes().any(|b| matches!(b, b'.' | b'e' | b'E')) => {
            if let Some(decimal) = short_decimal(text) {
                out.push_ascii(decimal);
                return Ok(());
            }
            let value = text.parse::<f64>().map_err(|e| e.to_string())?;
            out.push_ascii(&float_literal::format_float(value));
        }
        _ if text == "-0" => out.push_ascii("0"),
        _ => out.push_ascii(text),
    }
    Ok(())
}

impl exports::pyloros::hooks::handler::Guest for ContextHook {
    fn handle(event: String) -> Result<String, String> {
        if !event.trim_start().starts_with('{') {
            return Err("Expected a JSON context object".into());
        }
        let mut out = DisplayOutput::default();
        object(&event, &mut out)?;
        out.push_ascii("\n");
        Ok(out.text)
    }
}

export!(ContextHook);
