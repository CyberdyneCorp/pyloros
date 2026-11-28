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
    let fields: Fields = serde_json::from_str(text).map_err(|e| e.to_string())?;
    display_fields(&fields, out)
}

// Most small records need no hash table. Multi-field objects retain insertion
// order and replace duplicate values at their original position.
enum Fields<'a> {
    Empty,
    One(FieldName<'a>, &'a RawValue),
    Many(IndexMap<FieldName<'a>, &'a RawValue>),
}

impl<'de> serde::Deserialize<'de> for Fields<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = Fields<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a context object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let Some((key, value)) = map.next_entry()? else {
                    return Ok(Fields::Empty);
                };
                let Some(second) = map.next_entry()? else {
                    return Ok(Fields::One(key, value));
                };
                let mut fields = IndexMap::from([(key, value), second]);
                while let Some((key, value)) = map.next_entry()? {
                    fields.insert(key, value);
                }
                Ok(Fields::Many(fields))
            }
        }
        decoder.deserialize_map(Object)
    }
}

fn display_fields(fields: &Fields<'_>, out: &mut DisplayOutput) -> Result<(), String> {
    out.push_ascii("{");
    match fields {
        Fields::Empty => (),
        Fields::One(key, value) => member(key, value, out)?,
        Fields::Many(fields) => {
            for (index, (key, value)) in fields.iter().enumerate() {
                if out.chars == OUTPUT_LIMIT {
                    break;
                }
                if index > 0 {
                    out.push_ascii(", ");
                }
                member(key, value, out)?;
            }
        }
    }
    out.push_ascii("}");
    Ok(())
}

fn member(key: &FieldName<'_>, value: &RawValue, out: &mut DisplayOutput) -> Result<(), String> {
    if key
        .0
        .bytes()
        .all(|b| (b' '..=b'~').contains(&b) && !matches!(b, b'\'' | b'\\'))
    {
        out.push_ascii("'");
        out.push_ascii(&key.0);
        out.push_ascii("'");
    } else {
        out.push(&quoted_string(&key.0));
    }
    out.push_ascii(": ");
    render(value, out)
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
                let mut values = serde_json::Deserializer::from_str(rest).into_iter::<Fields>();
                let value = values
                    .next()
                    .expect("validated array member")
                    .map_err(|e| e.to_string())?;
                display_fields(&value, out)?;
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
        .position(|b| matches!(b, b'"' | b'\\') || !b.is_ascii_graphic() && b != b' ')
        .expect("validated JSON string ends with a quote");
    if content.as_bytes()[end] == b'"' {
        let value = &content[..end];
        let quote = if value.contains('\'') { "\"" } else { "'" };
        out.push_ascii(quote);
        out.push_ascii(value);
        out.push_ascii(quote);
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

// Integers below 10^15 are exactly representable in binary64, and the
// source prints integral floats of this magnitude in fixed-point notation.
fn scaled_integer(text: &str, out: &mut DisplayOutput) -> bool {
    let Some((mantissa, exponent)) = text.split_once(['e', 'E']) else {
        return false;
    };
    let Ok(power) = exponent.parse::<usize>() else {
        return false;
    };
    let digits = mantissa.trim_start_matches('-');
    if power > 15 || digits.len() + power > 15 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    out.push_ascii(mantissa);
    if digits != "0" {
        out.push_ascii(&"000000000000000"[..power]);
    }
    out.push_ascii(".0");
    true
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
            if scaled_integer(text, out) {
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
