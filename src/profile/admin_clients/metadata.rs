//! Administrative client registration fields and request validation.
use super::*;
use serde_json::Map;

#[derive(Default)]
pub(super) struct Metadata {
    pub name: String,
    pub description: Option<String>,
    pub scopes: BTreeSet<String>,
    pub audiences: Option<BTreeSet<String>>,
    pub ttl: i32,
    pub grants: BTreeSet<String>,
    pub kind: String,
    pub redirects: Option<BTreeSet<String>>,
    pub logout: Option<BTreeSet<String>>,
    pub audience: Option<String>,
    pub trusted: bool,
}

impl Fields<'_> {
    fn list(&mut self, key: &str, nullable: bool) -> Option<BTreeSet<String>> {
        let v = self.body.get(key)?;
        if nullable && v.is_null() {
            return None;
        }
        let Some(items) = v.as_array() else {
            self.issues.push(json!({"type":"list_type","loc":["body",key],"msg":"Input should be a valid list","input":v}));
            return None;
        };
        let mut values = BTreeSet::new();
        for (i, item) in items.iter().enumerate() {
            if let Some(s) = item.as_str() {
                values.insert(s.to_owned());
            } else {
                self.issues.push(json!({"type":"string_type","loc":["body",key,i],"msg":"Input should be a valid string","input":item}));
            }
        }
        Some(values)
    }
    fn ttl(&mut self) -> i32 {
        let Some(v) = self.body.get("max_token_ttl_s") else {
            return 3600;
        };
        let error =
            |k: &str, m: &str| json!({"type":k,"loc":["body","max_token_ttl_s"],"msg":m,"input":v});
        let issue = match crate::request_json::integer(v) {
            Ok(n @ 60..=86400) => return n as i32,
            Ok(..60) => {
                let mut e = error(
                    "greater_than_equal",
                    "Input should be greater than or equal to 60",
                );
                e["ctx"] = json!({"ge":"60"});
                e
            }
            Ok(_) => {
                let mut e = error(
                    "less_than_equal",
                    "Input should be less than or equal to 86400",
                );
                e["ctx"] = json!({"le":"86400"});
                e
            }
            Err((k, m)) => error(k, m),
        };
        self.issues.push(issue);
        3600
    }
    fn kind(&mut self) -> String {
        let Some(value) = self.body.get("client_type") else {
            return "confidential".into();
        };
        if let Some(kind @ ("confidential" | "public")) = value.as_str() {
            return kind.into();
        }
        self.issues.push(json!({"type":"literal_error","loc":["body","client_type"],"msg":"Input should be 'confidential' or 'public'","input":value,"ctx":{"expected":"'confidential' or 'public'"}}));
        String::new()
    }
}

pub(super) fn patch_fields(body: &Value) -> Result<Map<String, Value>, Vec<Value>> {
    let map = object(body)?;
    let mut fields = Fields {
        body: map,
        issues: vec![],
    };
    let mut patch = Map::new();
    for key in [
        "name",
        "description",
        "allowed_scopes",
        "allowed_audiences",
        "max_token_ttl_s",
        "active",
        "grant_types",
        "client_type",
        "redirect_uris",
        "post_logout_redirect_uris",
        "access_token_audience",
        "trusted",
    ] {
        let Some(input) = map.get(key) else { continue };
        let value = if input.is_null() {
            Value::Null
        } else {
            match key {
                "name" => json!(fields.string(key, Some(128), true)),
                "description" => json!(fields.string(key, Some(1024), false)),
                "access_token_audience" => json!(fields.string(key, None, false)),
                "active" | "trusted" => json!(fields.boolean(key)),
                "max_token_ttl_s" => json!(fields.ttl()),
                "client_type" => json!(fields.kind()),
                _ => json!(fields.list(key, true)),
            }
        };
        patch.insert(key.to_owned(), value);
    }
    if fields.issues.is_empty() {
        Ok(patch)
    } else {
        Err(fields.issues)
    }
}

impl Metadata {
    pub fn parse(body: Value) -> Result<Self, Vec<Value>> {
        let map = object(&body)?;
        let mut f = Fields {
            body: map,
            issues: Vec::new(),
        };
        let data = Self {
            name: f.string("name", Some(128), true).unwrap_or_default(),
            description: f.string("description", Some(1024), false),
            scopes: f.list("allowed_scopes", false).unwrap_or_default(),
            audiences: f.list("allowed_audiences", true),
            ttl: f.ttl(),
            grants: f
                .list("grant_types", true)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| ["client_credentials".to_owned()].into()),
            kind: f.kind(),
            redirects: f.list("redirect_uris", true),
            logout: f.list("post_logout_redirect_uris", true),
            audience: f.string("access_token_audience", None, false),
            trusted: f.boolean("trusted"),
        };
        if f.issues.is_empty() {
            Ok(data)
        } else {
            Err(f.issues)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_empty_grant_list_uses_the_service_default() {
        let data =
            Metadata::parse(json!({"name":"Example","grant_types":[],"allowed_audiences":[]}))
                .unwrap();
        assert_eq!(
            data.grants,
            BTreeSet::from(["client_credentials".to_owned()])
        );
        assert_eq!(data.audiences, Some(BTreeSet::new()));
    }

    #[test]
    fn captures_all_invalid_fields_in_schema_order() {
        let Err(issues) = Metadata::parse(
            json!({"name":null,"allowed_scopes":[1],"grant_types":false,"trusted":"unsure"}),
        ) else {
            panic!("accepted invalid metadata")
        };
        let fields: Vec<_> = issues.iter().map(|issue| &issue["loc"][1]).collect();
        assert_eq!(
            json!(fields),
            json!(["name", "allowed_scopes", "grant_types", "trusted"])
        );
    }
}
