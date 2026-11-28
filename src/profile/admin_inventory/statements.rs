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
    crate::stored_json::check_integers(raw)?;
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

fn stored_statements(raw: &str) -> sqlx::Result<Vec<Statement<Box<RawValue>, ExportCondition>>> {
    project(raw)
}

pub(super) async fn validate_stored_policy(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> sqlx::Result<()> {
    let (_, _, raw) = records(tx, Some(&[id]))
        .await?
        .pop()
        .ok_or(sqlx::Error::RowNotFound)?;
    stored_statements(&raw)?;
    Ok(())
}

fn transfer_statements(raw: &str, for_database: bool) -> Result<Box<RawValue>, sqlx::Error> {
    let statements = stored_statements(raw)?;
    let json = serde_json::to_string(&statements).map_err(|_| invalid())?;
    RawValue::from_string(crate::stored_json::project_fractions(json, for_database)?)
        .map_err(|_| invalid())
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
            statements: transfer_statements(&raw, false)?,
        });
    }
    Ok(policies)
}

pub(super) async fn refresh_imported_rules(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    #[derive(Deserialize)]
    struct StoredId {
        id: Uuid,
    }
    let (_, _, raw) = records(tx, Some(&[id]))
        .await?
        .pop()
        .ok_or(sqlx::Error::RowNotFound)?;
    let stored: Vec<StoredId> = serde_json::from_str(&raw).map_err(|_| invalid())?;
    let ids: Vec<Uuid> = stored.into_iter().map(|s| s.id).collect();
    let normalized = transfer_statements(&raw, true)?;
    refresh_observed(tx, &ids, &normalized).await
}

async fn refresh_observed(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
    normalized: &RawValue,
) -> Result<(), sqlx::Error> {
    // Refresh the rows this import actually observed. A concurrent import or
    // policy edit may already have replaced them by the time we get the lock.
    sqlx::query(
        "UPDATE iam_policy_statements s SET id=gen_random_uuid(),sort_order=e.position-1,
        actions=e.item->'actions',resources=e.item->'resources',conditions=e.item->'conditions'
        FROM jsonb_array_elements($2) WITH ORDINALITY AS e(item,position)
        WHERE s.id=($1::uuid[])[e.position::int]",
    )
    .bind(ids)
    .bind(sqlx::types::Json(normalized))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn records(
    tx: &mut Transaction<'_, Postgres>,
    ids: Option<&[Uuid]>,
) -> Result<Vec<(Value, DateTime<Utc>, String)>, sqlx::Error> {
    let mut query=sqlx::QueryBuilder::<Postgres>::new("SELECT jsonb_build_object('id',p.id,'name',p.name,'description',p.description,'version',p.version,
            'is_active',p.is_active,'chain_policy_id',p.chain_policy_id),p.created_at,
            COALESCE((SELECT json_agg(json_build_object('id',s.id,'sid',s.sid,'effect',s.effect,'actions',s.actions,
            'resources',s.resources,'conditions',s.conditions) ORDER BY s.sort_order)
            FROM iam_policy_statements s WHERE s.policy_id=p.id),'[]'::json)::text
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
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_stale_import_cannot_reapply_a_replaced_rule() -> Result<(), sqlx::Error> {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE iam_policy_statements(id uuid primary key,sort_order integer,actions jsonb,resources jsonb,conditions jsonb) ON COMMIT DROP")
            .execute(&mut *tx).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO iam_policy_statements(id) VALUES($1)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let current =
            serde_json::from_str(r#"[{"actions":["read"],"resources":[],"conditions":[]}]"#)
                .unwrap();
        let stale =
            serde_json::from_str(r#"[{"actions":["different"],"resources":[],"conditions":[]}]"#)
                .unwrap();
        refresh_observed(&mut tx, &[id], current).await?;
        refresh_observed(&mut tx, &[id], stale).await?;
        let rows =
            sqlx::query_as::<_, (Uuid, Value)>("SELECT id,actions FROM iam_policy_statements")
                .fetch_all(&mut *tx)
                .await?;
        assert_eq!(rows.len(), 1);
        assert_ne!(rows[0].0, id);
        assert_eq!(rows[0].1, json!(["read"]));
        tx.rollback().await?;
        Ok(())
    }

    #[test]
    fn export_uses_database_numeric_decoding_before_releasing_the_document() {
        let statement = |n: &str| {
            format!(
                r#"[{{"effect":"allow","sid":null,"actions":[{n}],"resources":[],"conditions":[]}}]"#
            )
        };
        assert!(transfer_statements(&statement(&"9".repeat(4301)), false).is_err());
        let doc = transfer_statements(&statement("1.2345678901234567890123"), false).unwrap();
        assert!(doc.get().contains("[1.2345678901234567]"));
        let doc =
            transfer_statements(&statement(&format!("{}.0", "9".repeat(310))), false).unwrap();
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
    fn policy_reads_check_integer_width_before_discarding_unexposed_values() {
        for width in [4300, 4301] {
            let number = "9".repeat(width);
            for (actions, conditions) in [
                (format!(r#"{{"view":{number}}}"#), "[]".to_owned()),
                (
                    "[]".to_owned(),
                    format!(
                        r#"[{{"operator":"StringEquals","key":"kind","value":"a","unused":{number}}}]"#
                    ),
                ),
            ] {
                let raw = format!(
                    r#"[{{"effect":"allow","actions":{actions},"resources":[],"conditions":{conditions}}}]"#
                );
                assert_eq!(project::<String, Condition>(&raw).is_ok(), width == 4300);
            }
        }
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
