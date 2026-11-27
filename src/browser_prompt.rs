//! Decide whether a browser authorization request needs interactive sign-in.
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use unicode_general_category::{GeneralCategory::DecimalNumber, get_general_category};

#[derive(Clone, Copy)]
pub enum SessionAuthentication {
    Anonymous,
    SignedIn { auth_time: Option<i64> },
}

#[derive(Debug, Eq, PartialEq)]
pub enum PromptDecision {
    Proceed,
    Login {
        fresh: bool,
    },
    Error {
        code: &'static str,
        description: String,
    },
}

struct Prompt {
    force: bool,
    silent: bool,
    max_age: Option<i64>,
    after: Option<i64>,
}

impl Prompt {
    fn parse(
        prompt: Option<&str>,
        max_age: Option<&str>,
        auth_after: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Self, String> {
        let values: BTreeSet<_> = prompt.unwrap_or_default().split_whitespace().collect();
        let silent = values.contains("none");
        if silent && values.len() > 1 {
            return Err("prompt=none cannot be combined with other values".into());
        }
        let unsupported: Vec<_> = values
            .iter()
            .copied()
            .filter(|v| !matches!(*v, "none" | "login" | "consent" | "select_account"))
            .collect();
        if !unsupported.is_empty() {
            return Err(format!(
                "unsupported prompt values: {}",
                quoted_list(&unsupported)
            ));
        }
        let after = seconds("auth_after", auth_after)?;
        if after.is_some_and(|t| t > now.timestamp().saturating_add(60)) {
            return Err("auth_after is in the future".into());
        }
        Ok(Self {
            force: values.contains("login"),
            silent,
            max_age: seconds("max_age", max_age)?,
            after,
        })
    }

    fn accepts(&self, session: SessionAuthentication, now: DateTime<Utc>) -> bool {
        let SessionAuthentication::SignedIn { auth_time } = session else {
            return false;
        };
        if self.force {
            return false;
        }
        if let Some(age) = self.max_age {
            let Some(time) = auth_time else { return false };
            let deadline = time.saturating_add(age);
            if now.timestamp() > deadline
                || (now.timestamp() == deadline && now.timestamp_subsec_micros() > 0)
            {
                return false;
            }
        }
        self.after
            .is_none_or(|after| auth_time.is_some_and(|t| t >= after))
    }
}

pub fn decide(
    prompt: Option<&str>,
    max_age: Option<&str>,
    after: Option<&str>,
    session: SessionAuthentication,
    now: DateTime<Utc>,
) -> PromptDecision {
    let prompt = match Prompt::parse(prompt, max_age, after, now) {
        Ok(p) => p,
        Err(description) => {
            return PromptDecision::Error {
                code: "invalid_request",
                description,
            };
        }
    };
    if prompt.accepts(session, now) {
        return PromptDecision::Proceed;
    }
    if prompt.silent {
        return PromptDecision::Error {
            code: "login_required",
            description: "interactive authentication required".into(),
        };
    }
    PromptDecision::Login {
        fresh: prompt.force || prompt.max_age.is_some() || prompt.after.is_some(),
    }
}

// Unicode decimal digits are arranged in consecutive groups of ten.
fn decimal(c: char) -> Option<i64> {
    if c.is_ascii_digit() {
        return Some(i64::from(c as u8 - b'0'));
    }
    if get_general_category(c) != DecimalNumber {
        return None;
    }
    let point = u32::from(c);
    let mut start = point;
    while char::from_u32(start - 1).is_some_and(|p| get_general_category(p) == DecimalNumber) {
        start -= 1;
    }
    Some(i64::from((point - start) % 10))
}

fn seconds(name: &str, value: Option<&str>) -> Result<Option<i64>, String> {
    let Some(raw) = value else { return Ok(None) };
    let invalid = || format!("{name} must be a non-negative integer");
    if raw.is_empty() {
        return Err(invalid());
    }
    raw.chars()
        .try_fold(0i64, |acc, c| {
            Ok(acc
                .saturating_mul(10)
                .saturating_add(decimal(c).ok_or_else(invalid)?))
        })
        .map(Some)
}

pub(crate) fn quoted_list(items: &[&str]) -> String {
    let quoted: Vec<_> = items
        .iter()
        .map(|s| {
            let quote = if s.contains('\'') && !s.contains('"') {
                '"'
            } else {
                '\''
            };
            let escaped = s
                .replace('\\', "\\\\")
                .replace(quote, &format!("\\{quote}"));
            format!("{quote}{escaped}{quote}")
        })
        .collect();
    format!("[{}]", quoted.join(", "))
}

pub fn login_location(
    login_url: &str,
    authorize_url: &str,
    fresh: bool,
    now: DateTime<Utc>,
) -> String {
    let target = if fresh {
        let (path, query) = authorize_url.split_once('?').unwrap_or((authorize_url, ""));
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if !matches!(key.as_ref(), "prompt" | "max_age" | "auth_after") {
                params.append_pair(&key, &value);
            }
        }
        params.append_pair("auth_after", &now.timestamp().to_string());
        format!("{path}?{}", encode_query(params))
    } else {
        authorize_url.into()
    };
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("next", &target);
    format!("{login_url}?{}", encode_query(params))
}

pub(crate) fn encode_query(mut params: url::form_urlencoded::Serializer<'_, String>) -> String {
    params.finish().replace("%7E", "~").replace('*', "%2A")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freshness_includes_fractional_seconds_and_requires_signed_evidence() {
        let now = DateTime::from_timestamp(100, 1000).unwrap();
        let session = SessionAuthentication::SignedIn {
            auth_time: Some(90),
        };
        assert_eq!(
            decide(None, Some("10"), None, session, now),
            PromptDecision::Login { fresh: true }
        );
        assert_eq!(
            decide(None, Some("١١"), None, session, now),
            PromptDecision::Proceed
        );
        assert_eq!(
            decide(None, None, Some("90"), session, now),
            PromptDecision::Proceed
        );
        assert_eq!(
            decide(None, None, Some("91"), session, now),
            PromptDecision::Login { fresh: true }
        );
        assert!(matches!(
            decide(
                Some("none"),
                Some("0"),
                None,
                SessionAuthentication::SignedIn { auth_time: None },
                now
            ),
            PromptDecision::Error {
                code: "login_required",
                ..
            }
        ));
    }

    #[test]
    fn return_trip_preserves_repeated_values_and_removes_fresh_login_triggers() {
        let now = DateTime::from_timestamp(100, 0).unwrap();
        let location = login_location(
            "https://id.example/login",
            "https://id.example/authorize?prompt=login&x=a%2Bb&x=&max_age=1&auth_after=0",
            true,
            now,
        );
        let url = url::Url::parse(&location).unwrap();
        assert_eq!(
            url.query_pairs().next().unwrap().1,
            "https://id.example/authorize?x=a%2Bb&x=&auth_after=100"
        );
    }
}
