use super::*;
use crate::request_json::token_field;
pub(super) struct Invitation {
    pub email: String,
    pub name: Option<String>,
    pub locale: Option<String>,
}

fn optional(body: &Value, key: &str, min: usize, max: usize) -> Result<Option<String>, Value> {
    if body[key].is_null() {
        return Ok(None);
    }
    token_field(body.clone(), key, min, max).map(Some)
}

fn name(body: &Value) -> Result<Option<String>, Value> {
    let Some(raw) = optional(body, "name", 1, 128)? else {
        return Ok(None);
    };
    let name = raw.trim();
    let lower = name.to_lowercase();
    if name.is_empty()
        || name.contains(['<', '>'])
        || lower.contains("://")
        || lower.contains("www.")
        || name.chars().any(crate::browser_prompt::unprintable)
    {
        let reason = "name must be plain text without links or markup";
        return Err(
            json!({"type":"value_error","loc":["body","name"],"input":raw,"msg":format!("Value error, {reason}"),"ctx":{"error":reason}}),
        );
    }
    Ok(Some(name.to_owned()))
}
fn locale(body: &Value) -> Result<Option<String>, Value> {
    let locale = optional(body, "locale", 2, 16)?;
    if locale
        .as_ref()
        .is_some_and(|s| !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    {
        let pattern = "^[A-Za-z0-9-]+$";
        return Err(
            json!({"type":"string_pattern_mismatch","loc":["body","locale"],"input":locale,"msg":format!("String should match pattern '{pattern}'"),"ctx":{"pattern":pattern}}),
        );
    }
    Ok(locale)
}
pub(super) fn parse(body: Value) -> Result<Invitation, Vec<Value>> {
    admin_fields::object(&body)?;
    match (
        crate::login_http::email_field(&body),
        name(&body),
        locale(&body),
    ) {
        (Ok(email), Ok(name), Ok(locale)) => Ok(Invitation {
            email: email.to_lowercase(),
            name,
            locale,
        }),
        (email, name, locale) => Err(email
            .err()
            .unwrap_or_default()
            .into_iter()
            .chain(name.err())
            .chain(locale.err())
            .collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_normalizes_the_address_and_preserves_only_plain_name_hints() {
        let invite =
            parse(json!({"email":"Invite@Example.com","name":"  Αθηνά  ","locale":"el-GR"}))
                .unwrap();
        assert_eq!(invite.email, "invite@example.com");
        assert_eq!(invite.name.as_deref(), Some("Αθηνά"));
        assert_eq!(invite.locale.as_deref(), Some("el-GR"));
        for name in ["<member>", "WWW.Example.com", "user\u{200b}name", " \t "] {
            let issues = parse(json!({"email":"a@example.com","name":name,"locale":"en US"}))
                .err()
                .unwrap();
            assert_eq!(issues.len(), 2);
            assert_eq!(issues[0]["loc"], json!(["body", "name"]));
            assert_eq!(issues[1]["loc"], json!(["body", "locale"]));
        }
    }
}
