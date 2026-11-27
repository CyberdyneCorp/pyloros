use super::*;
use crate::chain_settings::Update;
use zeroize::Zeroizing;

pub(super) struct Input {
    pub patch: Update,
    pub mnemonic: Option<Zeroizing<String>>,
    pub index: i128,
    pub audit: Value,
}

const NAMES: [&str; 8] = [
    "enabled",
    "group_contract_address",
    "identity_contract_address",
    "mnemonic",
    "mnemonic_account_index",
    "policy_contract_address",
    "private_key",
    "rpc_url",
];

pub(super) fn parse(body: &Value) -> Result<Input, Vec<Value>> {
    let map = admin_fields::object(body)?;
    let mut fields = admin_fields::Fields {
        body: map,
        issues: vec![],
    };
    let mut patch = Update::default();
    if map.get("enabled").is_some_and(|v| !v.is_null()) {
        patch.enabled = Some(fields.boolean("enabled"));
    }
    patch.rpc_url = fields.string("rpc_url", None, false);
    patch.private_key = fields
        .string("private_key", None, false)
        .map(Zeroizing::new);
    let mnemonic = fields.string("mnemonic", None, false).map(Zeroizing::new);
    let index = index(&mut fields);
    patch.identity_contract_address = fields.string("identity_contract_address", None, false);
    patch.policy_contract_address = fields.string("policy_contract_address", None, false);
    patch.group_contract_address = fields.string("group_contract_address", None, false);
    if !fields.issues.is_empty() {
        return Err(fields.issues);
    }
    let changed: Vec<_> = NAMES.into_iter().filter(|k| map.contains_key(*k)).collect();
    let secrets: Vec<_> = ["mnemonic", "private_key"]
        .into_iter()
        .filter(|k| map.contains_key(*k))
        .collect();
    Ok(Input {
        patch,
        mnemonic,
        index,
        audit: json!({"changed_keys":changed,"secrets_changed":secrets}),
    })
}

fn index(fields: &mut admin_fields::Fields<'_>) -> i128 {
    let key = "mnemonic_account_index";
    let Some(value) = fields.body.get(key) else {
        return 0;
    };
    let issue = match crate::request_json::integer(value) {
        Ok(n) if n >= 0 => return n,
        Ok(_) => {
            json!({"type":"greater_than_equal","loc":["body",key],"msg":"Input should be greater than or equal to 0","input":value,"ctx":{"ge":"0"}})
        }
        Err((kind, msg)) => json!({"type":kind,"loc":["body",key],"msg":msg,"input":value}),
    };
    fields.issues.push(issue);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_contains_only_recognized_field_names_including_explicit_nulls() {
        let body = json!({"mnemonic":"sensitive phrase","private_key":null,"unknown":"outside","enabled":false});
        let input = parse(&body).unwrap();
        assert_eq!(
            input.audit,
            json!({"changed_keys":["enabled","mnemonic","private_key"],
            "secrets_changed":["mnemonic","private_key"]})
        );
        assert_eq!(input.patch.enabled, Some(false));
        assert!(input.patch.private_key.is_none());
    }
}
