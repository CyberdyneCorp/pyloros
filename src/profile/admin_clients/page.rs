use serde_json::{Value, json};
use std::collections::HashMap;

pub(super) struct Page {
    pub number: i128,
    pub size: i64,
    pub active_only: bool,
}
impl Page {
    pub fn parse(query: &str) -> Result<Self, Vec<Value>> {
        let fields: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let mut issues = Vec::new();
        let mut number = |name, default, max| {
            let Some(raw) = fields.get(name) else {
                return default;
            };
            match bounded(name, raw, max) {
                Ok(n) => n,
                Err(e) => {
                    issues.push(e);
                    default
                }
            }
        };
        let page = number("page", 1, None);
        let size = number("page_size", 50, Some(200)) as i64;
        let active_only = match fields
            .get("active_only")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("0" | "false" | "no" | "off" | "n" | "f") => false,
            Some("1" | "true" | "yes" | "on" | "y" | "t") => true,
            _ => {
                issues.push(json!({"type":"bool_parsing","loc":["query","active_only"],"msg":"Input should be a valid boolean, unable to interpret input","input":fields["active_only"]}));
                false
            }
        };
        if issues.is_empty() {
            Ok(Self {
                number: page,
                size,
                active_only,
            })
        } else {
            Err(issues)
        }
    }
}
fn bounded(name: &str, raw: &str, max: Option<i128>) -> Result<i128, Value> {
    let error =
        |kind: &str, msg: &str| json!({"loc":["query",name],"type":kind,"msg":msg,"input":raw});
    let digits = crate::query::integer(raw).map_err(|(k, m)| error(k, m))?;
    let n = digits.parse().unwrap_or_else(|_| {
        if digits.starts_with('-') {
            i128::MIN
        } else {
            i128::MAX
        }
    });
    let (kind, msg, ctx) = if n < 1 {
        (
            "greater_than_equal",
            "Input should be greater than or equal to 1",
            json!({"ge":"1"}),
        )
    } else if max.is_some_and(|m| n > m) {
        (
            "less_than_equal",
            "Input should be less than or equal to 200",
            json!({"le":"200"}),
        )
    } else {
        return Ok(n);
    };
    let mut e = error(kind, msg);
    e["ctx"] = ctx;
    Err(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_all_invalid_fields_in_contract_order() {
        let issues = Page::parse("active_only=maybe&page_size=201&page=-1")
            .err()
            .unwrap();
        let fields: Vec<_> = issues
            .iter()
            .map(|issue| (&issue["loc"][1], &issue["type"]))
            .collect();
        assert_eq!(
            json!(fields),
            json!([
                ["page", "greater_than_equal"],
                ["page_size", "less_than_equal"],
                ["active_only", "bool_parsing"]
            ])
        );
    }

    #[test]
    fn repeated_parameters_use_the_last_value() {
        let page = Page::parse("page=3&page=2.00&page_size=1_0&active_only=on").unwrap();
        assert_eq!((page.number, page.size, page.active_only), (2, 10, true));
    }
}
