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
    let fields: IndexMap<FieldName<'_>, &RawValue> =
        serde_json::from_str(text).map_err(|e| e.to_string())?;
    out.push("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if out.chars == OUTPUT_LIMIT {
            break;
        }
        if index > 0 {
            out.push(", ");
        }
        if key
            .0
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) && !matches!(b, b'\'' | b'\\'))
        {
            out.push("'");
            out.push(&key.0);
            out.push("'");
        } else {
            out.push(&quoted_string(&key.0));
        }
        out.push(": ");
        render(value, out)?;
    }
    out.push("}");
    Ok(())
}

fn array(text: &str, out: &mut DisplayOutput) -> Result<(), String> {
    let values: Vec<&RawValue> = serde_json::from_str(text).map_err(|e| e.to_string())?;
    out.push("[");
    for (index, value) in values.into_iter().enumerate() {
        if out.chars == OUTPUT_LIMIT {
            break;
        }
        if index > 0 {
            out.push(", ");
        }
        render(value, out)?;
    }
    out.push("]");
    Ok(())
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
        b'n' => out.push("None"),
        b't' => out.push("True"),
        b'f' => out.push("False"),
        _ if text.contains(['.', 'e', 'E']) => {
            let value = text.parse::<f64>().map_err(|e| e.to_string())?;
            out.push(&float_literal::format_float(value));
        }
        _ if text == "-0" => out.push("0"),
        _ => out.push(text),
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
        out.push("\n");
        Ok(out.text)
    }
}

export!(ContextHook);
