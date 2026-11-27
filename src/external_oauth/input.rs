use serde_json::{Value, json};
use std::collections::HashMap;

pub(super) struct Start {
    pub redirect: bool,
    pub mode: String,
    pub target: Option<String>,
    pub port: Option<i32>,
    pub challenge: Option<String>,
}

impl Start {
    pub(super) fn parse(query: &str) -> Result<Self, Vec<Value>> {
        let mut fields: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let mut issues = Vec::new();
        let redirect = match fields
            .get("redirect")
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("0" | "false" | "no" | "off" | "n" | "f") => false,
            Some("1" | "true" | "yes" | "on" | "y" | "t") => true,
            _ => {
                issues.push(json!({"type":"bool_parsing","loc":["query","redirect"],"msg":"Input should be a valid boolean, unable to interpret input","input":fields["redirect"]}));
                false
            }
        };
        let mode = fields
            .remove("return_mode")
            .unwrap_or_else(|| "cookie".into());
        if !matches!(mode.as_str(), "cookie" | "fragment" | "cli") {
            issues.push(json!({"type":"string_pattern_mismatch","loc":["query","return_mode"],"msg":"String should match pattern '^(cookie|fragment|cli)$'","input":mode,"ctx":{"pattern":"^(cookie|fragment|cli)$"}}));
        }
        let port = fields.get("cli_port").and_then(|value| {
            integer_port(value).map_err(|(kind,message)| {
                issues.push(json!({"type":kind, "loc":["query","cli_port"], "msg":message, "input":value}));
            }).ok()
        });
        if !issues.is_empty() {
            return Err(issues);
        }
        Ok(Self {
            redirect,
            mode,
            target: fields.remove("frontend_redirect"),
            port,
            challenge: fields.remove("code_challenge"),
        })
    }

    pub(super) fn validate(
        &self,
        allowed: &std::collections::BTreeSet<String>,
    ) -> Result<(), &'static str> {
        if self.mode == "cli" {
            if self.target.is_some() {
                return Err("frontend_redirect is not used in cli mode");
            }
            if !self.port.is_some_and(|p| (1024..=65535).contains(&p)) {
                return Err("cli_port must be between 1024 and 65535");
            }
            if !self.challenge.as_deref().is_some_and(|raw| {
                // Legacy initiation accepts one terminal LF. Persist the original challenge for exchange.
                let s = raw.strip_suffix('\n').unwrap_or(raw);
                s.len() == 43
                    && s.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            }) {
                return Err("code_challenge must be a base64url S256 challenge");
            }
            return Ok(());
        }
        match self.target.as_deref() {
            None if self.mode == "cookie" => Ok(()),
            Some(url) if !url.is_empty() && !url.contains("..") && allowed.contains(url) => Ok(()),
            _ => Err("frontend_redirect not permitted"),
        }
    }
}

// Retain syntactically valid out-of-range ports for the CLI-specific range error.
fn integer_port(raw: &str) -> Result<i32, (&'static str, &'static str)> {
    const INVALID: (&str, &str) = (
        "int_parsing",
        "Input should be a valid integer, unable to parse string as an integer",
    );
    let n = raw.trim();
    let whole = match n.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() && fraction.bytes().all(|b| b == b'0') => {
            whole
        }
        Some(_) => return Err(INVALID),
        None => n,
    };
    let digits = whole.strip_prefix(['-', '+']).unwrap_or(whole);
    if digits.is_empty()
        || !digits
            .split('_')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(INVALID);
    }
    let normalized = digits.replace('_', "");
    let significant = normalized.trim_start_matches('0');
    if significant.len() > 4300 {
        return Err((
            "int_parsing_size",
            "Unable to parse input string as an integer, exceeded maximum size",
        ));
    }
    Ok(whole.replace('_', "").parse().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_port_syntax_and_range_have_distinct_responses() {
        assert!(Start::parse("cli_port=5.").is_err());
        let options = Start::parse("return_mode=cli&cli_port=100000000000").unwrap();
        assert_eq!(
            options.validate(&Default::default()),
            Err("cli_port must be between 1024 and 65535")
        );
        let options = Start::parse(&format!(
            "cli_port=4_123.00&return_mode=cli&code_challenge={}",
            "a".repeat(43)
        ))
        .unwrap();
        assert_eq!(options.port, Some(4123));
        assert!(options.validate(&Default::default()).is_ok());
    }

    #[test]
    fn terminal_line_feed_in_cli_challenge_is_preserved_for_exchange() {
        let challenge = "q".repeat(43);
        let query = format!("return_mode=cli&cli_port=4444&code_challenge={challenge}");
        let input = Start::parse(&format!("{query}%0A")).unwrap();
        assert!(input.validate(&Default::default()).is_ok());
        assert_eq!(input.challenge.unwrap(), format!("{challenge}\n"));
        for suffix in ["%0D", "%0A%0A"] {
            assert!(
                Start::parse(&format!("{query}{suffix}"))
                    .unwrap()
                    .validate(&Default::default())
                    .is_err()
            );
        }
    }

    #[test]
    fn frontend_destination_matches_a_whole_registered_url() {
        let allowed = ["https://client.example/finish".to_owned()].into();
        for (target, accepted) in [
            ("https://client.example/finish", true),
            ("https://client.example/finish/next", false),
            ("https://client.example/finish?x", false),
        ] {
            let input =
                Start::parse(&format!("return_mode=fragment&frontend_redirect={target}")).unwrap();
            assert_eq!(input.validate(&allowed).is_ok(), accepted);
        }
    }
}
