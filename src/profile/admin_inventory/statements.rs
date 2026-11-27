//! Project stored policy statements, including historical JSONB collection forms.
use super::*;
use serde::{Deserialize, de::DeserializeOwned};
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

use crate::iam_evaluation::Condition;

fn invalid() -> sqlx::Error {
    sqlx::Error::Decode("invalid stored IAM statement".into())
}

fn empty_scalar(raw: &str) -> bool {
    matches!(raw, "null" | "false" | "\"\"") || raw.parse::<f64>() == Ok(0.0)
}

fn collection<T: DeserializeOwned>(raw: &RawValue) -> Result<Vec<T>, sqlx::Error> {
    let data = raw.get();
    let text_items = match data.as_bytes()[0] {
        b'[' => return serde_json::from_str(data).map_err(|_| invalid()),
        b'{' => {
            let fields: indexmap::IndexMap<String, &RawValue> =
                serde_json::from_str(data).map_err(|_| invalid())?;
            fields.into_keys().collect()
        }
        b'"' => serde_json::from_str::<String>(data)
            .map_err(|_| invalid())?
            .chars()
            .map(|c| c.to_string())
            .collect::<Vec<_>>(),
        _ if empty_scalar(data) => return Ok(Vec::new()),
        _ => return Err(invalid()),
    };
    text_items
        .into_iter()
        .map(|s| serde_json::from_value(Value::String(s)).map_err(|_| invalid()))
        .collect()
}

fn conditions<T: DeserializeOwned>(raw: &RawValue) -> Result<Vec<T>, sqlx::Error> {
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

#[derive(Serialize)]
struct Statement<T, C> {
    effect: String,
    sid: Option<String>,
    actions: Vec<T>,
    resources: Vec<T>,
    conditions: Vec<C>,
}

fn project<T: DeserializeOwned, C: DeserializeOwned>(
    raw: &str,
) -> Result<Vec<Statement<T, C>>, sqlx::Error> {
    let stored: Vec<StoredStatement<'_>> = serde_json::from_str(raw).map_err(|_| invalid())?;
    stored
        .into_iter()
        .map(|s| {
            if !matches!(s.effect.as_str(), "allow" | "deny") {
                return Err(invalid());
            }
            Ok(Statement {
                effect: s.effect,
                sid: s.sid,
                actions: collection(s.actions)?,
                resources: collection(s.resources)?,
                conditions: conditions(s.conditions)?,
            })
        })
        .collect()
}

pub(super) async fn policies(
    tx: &mut Transaction<'_, Postgres>,
    id: Option<Uuid>,
) -> Result<Vec<Value>, sqlx::Error> {
    load(tx, id.as_ref().map(std::slice::from_ref)).await
}

pub(super) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    ids: Option<&[Uuid]>,
) -> Result<Vec<Value>, sqlx::Error> {
    let rows = records(tx, ids).await?;
    let mut policies = Vec::with_capacity(rows.len());
    for (mut policy, created, raw) in rows {
        policy["created_at"] = json!(timestamp(created));
        policy["statements"] = json!(project::<String, Condition>(&raw)?);
        policies.push(policy);
    }
    Ok(policies)
}

// Export retains historical JSON values in action, resource and condition fields.
#[derive(Deserialize, Serialize)]
struct ExportCondition {
    operator: crate::iam_evaluation::Operator,
    key: Box<RawValue>,
    value: Box<RawValue>,
}

#[derive(Serialize)]
pub(super) struct ExportPolicy {
    #[serde(flatten)]
    header: Value,
    statements: Box<RawValue>,
}

fn export_statements(raw: &str) -> Result<Box<RawValue>, sqlx::Error> {
    use crate::request_json::iam_document::unquoted_tokens;
    // PostgreSQL renders JSONB numbers in decimal notation. The reference store
    // decodes integers up to 4300 digits and fractional values as binary64.
    for (_, token) in unquoted_tokens(raw) {
        let digits = token.trim_start_matches('-');
        if digits.len() > 4300 && digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
    }
    let statements = project::<Box<RawValue>, ExportCondition>(raw)?;
    let json = serde_json::to_string(&statements).map_err(|_| invalid())?;
    let mut normalized = String::new();
    let mut cursor = 0;
    for (start, token) in unquoted_tokens(&json) {
        if token.contains(['.', 'e', 'E'])
            && token.starts_with(|c: char| c.is_ascii_digit() || c == '-')
        {
            let value = token.parse::<f64>().map_err(|_| invalid())?;
            normalized.push_str(&json[cursor..start]);
            normalized.push_str(&serde_json::to_string(&value).map_err(|_| invalid())?);
            cursor = start + token.len();
        }
    }
    if cursor == 0 {
        return RawValue::from_string(json).map_err(|_| invalid());
    }
    normalized.push_str(&json[cursor..]);
    RawValue::from_string(normalized).map_err(|_| invalid())
}

pub(super) async fn export(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ExportPolicy>, sqlx::Error> {
    let rows = records(tx, None).await?;
    let mut policies = Vec::with_capacity(rows.len());
    for (row, _, raw) in rows {
        let header = json!({
            "local_id": row["id"],
            "ref": row["chain_policy_id"],
            "name": row["name"],
            "description": row["description"],
            "version": row["version"]
        });
        policies.push(ExportPolicy {
            header,
            statements: export_statements(&raw)?,
        });
    }
    Ok(policies)
}

async fn records(
    tx: &mut Transaction<'_, Postgres>,
    ids: Option<&[Uuid]>,
) -> Result<Vec<(Value, DateTime<Utc>, String)>, sqlx::Error> {
    let mut query=sqlx::QueryBuilder::<Postgres>::new("SELECT jsonb_build_object('id',p.id,'name',p.name,'description',p.description,'version',p.version,
            'is_active',p.is_active,'chain_policy_id',p.chain_policy_id),p.created_at,
            COALESCE((SELECT jsonb_agg(jsonb_build_object('sid',s.sid,'effect',s.effect,'actions',s.actions,
            'resources',s.resources,'conditions',s.conditions) ORDER BY s.sort_order)
            FROM iam_policy_statements s WHERE s.policy_id=p.id),'[]'::jsonb)::text
            FROM iam_policies p");
    if let Some(ids) = ids {
        query.push(" JOIN unnest(").push_bind(ids).push("::uuid[]) WITH ORDINALITY requested(id,position) ON requested.id=p.id ORDER BY requested.position");
    } else {
        query.push(" ORDER BY p.name");
    }
    query.build_query_as().fetch_all(&mut **tx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_uses_database_numeric_decoding_before_releasing_the_document() {
        let statement = |n: &str| {
            format!(
                r#"[{{"effect":"allow","sid":null,"actions":[{n}],"resources":[],"conditions":[]}}]"#
            )
        };
        assert!(export_statements(&statement(&"9".repeat(4301))).is_err());
        let doc = export_statements(&statement("1.2345678901234567890123")).unwrap();
        assert!(doc.get().contains("[1.2345678901234567]"));
        let doc = export_statements(&statement(&format!("{}.0", "9".repeat(310)))).unwrap();
        assert!(doc.get().contains("[null]"));
    }
    #[test]
    fn exporting_legacy_statements_preserves_large_numbers_and_condition_data() {
        let raw = r#"[{"effect":"allow","sid":null,"actions":[123456789012345678901234567890],"resources":"ab","conditions":[{"operator":"StringEquals","key":42,"value":null}]}]"#;
        let statements = project::<Box<RawValue>, ExportCondition>(raw).unwrap();
        let encoded = serde_json::to_string(&statements).unwrap();
        assert!(encoded.contains("123456789012345678901234567890"));
        assert!(encoded.contains(r#""resources":["a","b"]"#));
        assert!(encoded.contains(r#""key":42,"value":null"#));
        assert!(project::<String, Condition>(raw).is_err());
    }
    #[test]
    fn condition_requires_named_fields_even_when_an_array_has_the_correct_arity() {
        let array = serde_json::from_str(r#"[["IpAddress","scope","local"]]"#).unwrap();
        assert!(conditions::<Condition>(array).is_err());
        let named = serde_json::from_str(
            r#"[{"operator":"IpAddress","key":"scope","value":"local","ignored":1e999}]"#,
        )
        .unwrap();
        assert_eq!(conditions::<Condition>(named).unwrap().len(), 1);
    }
}
