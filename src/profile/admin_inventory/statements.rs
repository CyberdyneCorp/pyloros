//! Project stored policy statements, including historical JSONB collection forms.
use super::*;
use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Deserialize)]
struct StoredStatement<'a> {
    effect: String,
    sid: Option<String>,
    #[serde(borrow)]
    actions: &'a RawValue,
    resources: &'a RawValue,
    conditions: &'a RawValue,
}

#[derive(Deserialize, Serialize)]
struct Condition {
    operator: Operator,
    key: String,
    value: String,
}

#[derive(Deserialize, Serialize)]
enum Operator {
    StringEquals,
    StringNotEquals,
    NumericEquals,
    NumericLessThan,
    NumericGreaterThan,
    DateTimeLessThan,
    DateTimeGreaterThan,
    IpAddress,
    NotIpAddress,
}

fn invalid() -> sqlx::Error {
    sqlx::Error::Decode("invalid stored IAM statement".into())
}

fn empty_scalar(raw: &str) -> bool {
    matches!(raw, "null" | "false" | "\"\"") || raw.parse::<f64>() == Ok(0.0)
}

fn strings(raw: &RawValue) -> Result<Vec<String>, sqlx::Error> {
    let data = raw.get();
    match data.as_bytes()[0] {
        b'[' => serde_json::from_str(data).map_err(|_| invalid()),
        b'{' => {
            let fields: indexmap::IndexMap<String, &RawValue> =
                serde_json::from_str(data).map_err(|_| invalid())?;
            Ok(fields.into_keys().collect())
        }
        b'"' => Ok(serde_json::from_str::<String>(data)
            .map_err(|_| invalid())?
            .chars()
            .map(|c| c.to_string())
            .collect()),
        _ if empty_scalar(data) => Ok(Vec::new()),
        _ => Err(invalid()),
    }
}

fn conditions(raw: &RawValue) -> Result<Vec<Condition>, sqlx::Error> {
    let data = raw.get();
    if data == "{}" || empty_scalar(data) {
        return Ok(Vec::new());
    }
    let entries: Vec<&RawValue> = serde_json::from_str(data).map_err(|_| invalid())?;
    entries
        .into_iter()
        .map(|entry| {
            if !entry.get().starts_with('{') {
                return Err(invalid());
            }
            serde_json::from_str(entry.get()).map_err(|_| invalid())
        })
        .collect()
}

impl StoredStatement<'_> {
    fn project(self) -> Result<Value, sqlx::Error> {
        if !matches!(self.effect.as_str(), "allow" | "deny") {
            return Err(invalid());
        }
        Ok(
            json!({"effect":self.effect,"actions":strings(self.actions)?,"resources":strings(self.resources)?,"conditions":conditions(self.conditions)?,"sid":self.sid}),
        )
    }
}

pub(super) async fn policies(
    tx: &mut Transaction<'_, Postgres>,
    id: Option<Uuid>,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut query=sqlx::QueryBuilder::<Postgres>::new(
        "SELECT jsonb_build_object('id',p.id,'name',p.name,'description',p.description,'version',p.version,
            'is_active',p.is_active,'chain_policy_id',p.chain_policy_id),p.created_at,
            COALESCE((SELECT jsonb_agg(jsonb_build_object('sid',s.sid,'effect',s.effect,'actions',s.actions,
            'resources',s.resources,'conditions',s.conditions) ORDER BY s.sort_order)
            FROM iam_policy_statements s WHERE s.policy_id=p.id),'[]'::jsonb)::text
            FROM iam_policies p"
    );
    if let Some(id) = id {
        query.push(" WHERE p.id=").push_bind(id);
    } else {
        query.push(" ORDER BY p.name");
    }
    let rows = query
        .build_query_as::<(Value, DateTime<Utc>, String)>()
        .fetch_all(&mut **tx)
        .await?;
    let mut policies = Vec::with_capacity(rows.len());
    for (mut policy, created, raw) in rows {
        let stored: Vec<StoredStatement<'_>> = serde_json::from_str(&raw).map_err(|_| invalid())?;
        let statements = stored
            .into_iter()
            .map(StoredStatement::project)
            .collect::<Result<Vec<_>, _>>()?;
        policy["created_at"] = json!(timestamp(created));
        policy["statements"] = Value::Array(statements);
        policies.push(policy);
    }
    Ok(policies)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn condition_requires_named_fields_even_when_an_array_has_the_correct_arity() {
        let array = serde_json::from_str(r#"[["IpAddress","scope","local"]]"#).unwrap();
        assert!(conditions(array).is_err());
        let named = serde_json::from_str(
            r#"[{"operator":"IpAddress","key":"scope","value":"local","ignored":1e999}]"#,
        )
        .unwrap();
        assert_eq!(conditions(named).unwrap().len(), 1);
    }
}
