use serde_json::Value;
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
        let (page, size) = crate::query::pagination(&fields, 50, 200, &mut issues);
        let active_only = crate::query::active_only(fields.get("active_only").map(|v| v.as_ref()))
            .unwrap_or_else(|e| {
                issues.push(e);
                false
            });
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
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
