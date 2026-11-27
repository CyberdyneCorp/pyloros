use super::*;

pub(super) const KEYS: &[&str] = &[
    "user_id",
    "organization_id",
    "product_key",
    "plan",
    "expires_at",
];

pub(super) fn parse(body: Value) -> Result<Grant, Vec<Value>> {
    let mut fields = admin_fields::Fields {
        body: admin_fields::object(&body)?,
        issues: vec![],
    };
    let user = owner(&mut fields, "user_id");
    let org = owner(&mut fields, "organization_id");
    let product = fields.string("product_key", Some(64), true);
    let plan = fields.string("plan", Some(64), false);
    let expires = fields
        .body
        .get("expires_at")
        .filter(|v| !v.is_null())
        .and_then(|v| {
            datetime::parse(v)
                .map_err(|mut issue| {
                    issue["loc"] = json!(["body", "expires_at"]);
                    fields.issues.push(issue)
                })
                .ok()
        });
    if !fields.issues.is_empty() {
        return Err(fields.issues);
    }
    Ok(Grant {
        user,
        org,
        product: product.expect("validated product"),
        plan,
        expires,
    })
}

fn owner(fields: &mut admin_fields::Fields<'_>, name: &str) -> Option<Uuid> {
    let v = fields.body.get(name).filter(|v| !v.is_null())?;
    let parsed = match v.as_str() {
        Some(s) => crate::query::uuid_field(s, "body", name),
        None => Err(
            json!({"type":"uuid_type","loc":["body",name],"msg":"UUID input should be a string, bytes or UUID object"}),
        ),
    };
    parsed.map_err(|e| fields.issues.push(e)).ok()
}
