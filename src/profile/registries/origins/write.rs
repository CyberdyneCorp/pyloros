//! Transactional changes to browser origins and their redirect policies.
use super::*;
use crate::{browser_prompt::quoted_string, grant_response::SessionOrigin, oauth_uri};
use serde_json::Map;

pub(in crate::profile::registries) struct Request {
    target: Option<Uuid>,
    fields: Value,
}

impl Request {
    pub(in crate::profile::registries) fn parse(
        target: Option<&str>,
        body: &Value,
    ) -> Result<Self, Vec<Value>> {
        let id = target
            .map(|s| crate::query::path_uuid(s, "origin_id"))
            .transpose();
        let mut issues: Vec<_> = id.as_ref().err().cloned().into_iter().collect();
        let body = match admin_fields::object(body) {
            Ok(body) => body,
            Err(errors) => {
                issues.extend(errors);
                return Err(issues);
            }
        };
        let mut input = admin_fields::Fields { body, issues };
        let mut fields = Map::new();
        let patch = target.is_some();
        if !patch {
            fields.insert(
                "origin".into(),
                json!(input.string("origin", Some(255), true)),
            );
        }
        if body.contains_key("name") {
            fields.insert("name".into(), json!(input.string("name", Some(128), false)));
        }
        for key in ["cors", "dcr_redirect"] {
            bool_field(&mut input, &mut fields, key, patch);
        }
        let key = "fragment_redirect_uris";
        if let Some(value) = body.get(key) {
            let start = input.issues.len();
            let values = input.string_list(key, patch);
            if let Some(n) = value.as_array().map(Vec::len).filter(|n| *n > 32) {
                input.issues.truncate(start);
                input.issues.push(json!({"type":"too_long","loc":["body",key],"msg":format!("List should have at most 32 items after validation, not {n}"),"input":value,"ctx":{"field_type":"List","max_length":"32","actual_length":n.to_string()}}));
            }
            fields.insert(key.into(), json!(values));
        }
        if patch {
            bool_field(&mut input, &mut fields, "active", true);
        }
        if !input.issues.is_empty() {
            return Err(input.issues);
        }
        Ok(Self {
            target: id.unwrap(),
            fields: fields.into(),
        })
    }

    pub(in crate::profile::registries) async fn apply(
        self,
        mut tx: Transaction<'static, Postgres>,
        registry: &crate::discovery::ScopeRegistry,
        actor: (Uuid, Option<&str>),
        origin: SessionOrigin<'_>,
    ) -> Result<Response, sqlx::Error> {
        let saved = match self.target {
            Some(id) => self.patch(&mut tx, id).await?,
            None => self.insert(&mut tx, actor.0).await?,
        };
        let row = match saved {
            Ok(row) => row,
            Err(response) => return Ok(*response),
        };
        let (status, action, meta) = if self.target.is_some() {
            (StatusCode::OK, "oauth_web_origin.update", self.fields)
        } else {
            (
                StatusCode::CREATED,
                "oauth_web_origin.create",
                json!({"origin":row["origin"],"cors":row["cors"],"dcr_redirect":row["dcr_redirect"]}),
            )
        };
        crate::admin_audit::append(
            &mut tx,
            action,
            Some(actor),
            ("oauth_web_origin", row["id"].as_str().expect("UUID column")),
            meta,
            origin,
        )
        .await?;
        registry.commit(tx).await?;
        Ok((status, Json(row)).into_response())
    }

    fn redirects(&self, origin: &str) -> Result<Option<String>, String> {
        let Some(items) = self.fields["fragment_redirect_uris"].as_array() else {
            return Ok(None);
        };
        let mut uris = BTreeSet::new();
        for uri in items
            .iter()
            .filter_map(Value::as_str)
            .map(mutation::trimmed)
            .filter(|s| !s.is_empty())
        {
            if uri.contains("..") || oauth_uri::redirect_origin(uri).as_deref() != Some(origin) {
                return Err(format!(
                    "fragment redirect must be a URL under {origin}: {}",
                    quoted_string(uri)
                ));
            }
            uris.insert(uri);
        }
        Ok(Some(uris.into_iter().collect::<Vec<_>>().join(" ")))
    }

    async fn insert(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        actor: Uuid,
    ) -> Result<Saved, sqlx::Error> {
        let value = mutation::trimmed(self.fields["origin"].as_str().expect("validated origin"));
        let origin = match oauth_uri::bare_origin(value) {
            Ok(v) => v,
            Err(e) => return Ok(invalid(e)),
        };
        let redirects = match self.redirects(&origin) {
            Ok(v) => v.unwrap_or_default(),
            Err(e) => return Ok(invalid(e)),
        };
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_web_origins WHERE origin=$1)")
                .bind(&origin)
                .fetch_one(&mut **tx)
                .await?;
        if exists {
            return Ok(Err(Box::new(problem(
                StatusCode::CONFLICT,
                &format!("web origin {} already exists", quoted_string(&origin)),
            ))));
        }
        let row = sqlx::query(
            "INSERT INTO oauth_web_origins
                (id, origin, name, cors, dcr_redirect, fragment_redirect_uris, active, created_by_user_id)
             VALUES ($1,$2,$3,$4,$5,$6,true,$7) RETURNING *",
        )
            .bind(Uuid::new_v4())
        .bind(origin)
        .bind(self.fields["name"].as_str())
        .bind(self.fields["cors"].as_bool().unwrap_or(true))
        .bind(self.fields["dcr_redirect"].as_bool().unwrap_or(false))
        .bind(redirects)
        .bind(actor)
        .try_map(document)
        .fetch_one(&mut **tx)
        .await?;
        Ok(Ok(row))
    }

    async fn patch(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Saved, sqlx::Error> {
        let row = sqlx::query(&format!("{SELECT} WHERE id=$1 FOR UPDATE"))
            .bind(id)
            .try_map(document)
            .fetch_optional(&mut **tx)
            .await?;
        let Some(row) = row else {
            return Ok(Err(Box::new(problem(
                StatusCode::NOT_FOUND,
                &format!("not found: {id}"),
            ))));
        };
        let redirects = match self.redirects(row["origin"].as_str().expect("origin column")) {
            Ok(Some(s)) => s,
            Ok(None) => row["fragment_redirect_uris"]
                .as_array()
                .expect("redirect list")
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            Err(e) => return Ok(invalid(e)),
        };
        let flag = |key: &str| self.fields[key].as_bool().unwrap_or(row[key] == true);
        let row = sqlx::query(
            "UPDATE oauth_web_origins SET name=$2,cors=$3,dcr_redirect=$4,fragment_redirect_uris=$5,active=$6,
            updated_at=CASE WHEN (name,cors,dcr_redirect,fragment_redirect_uris,active) IS DISTINCT FROM ($2,$3,$4,$5,$6) THEN now() ELSE updated_at END WHERE id=$1 RETURNING *",
        )
        .bind(id)
            .bind(self.fields.get("name").unwrap_or(&row["name"]).as_str())
        .bind(flag("cors"))
        .bind(flag("dcr_redirect"))
        .bind(redirects)
        .bind(flag("active"))
        .try_map(document)
        .fetch_one(&mut **tx)
        .await?;
        Ok(Ok(row))
    }
}

fn bool_field(
    input: &mut admin_fields::Fields<'_>,
    fields: &mut Map<String, Value>,
    key: &str,
    nullable: bool,
) {
    if let Some(v) = input.body.get(key) {
        let value = if nullable && v.is_null() {
            Value::Null
        } else {
            json!(input.boolean(key))
        };
        fields.insert(key.into(), value);
    }
}

type Saved = Result<Value, Box<Response>>;
fn invalid(message: String) -> Saved {
    Err(Box::new(problem(StatusCode::BAD_REQUEST, &message)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_preserves_submitted_redirects_and_null_flags_for_audit() {
        let target = "https://example.com/done";
        let request = Request::parse(
            Some("00000000-0000-0000-0000-000000000001"),
            &json!({"fragment_redirect_uris":[target,target],"cors":null,"origin":"ignored"}),
        )
        .unwrap();
        assert_eq!(
            request.fields,
            json!({"fragment_redirect_uris":[target,target],"cors":null})
        );
        assert_eq!(
            request.redirects("https://example.com").unwrap().as_deref(),
            Some(target)
        );
        assert!(request.redirects("https://other.example").is_err());
    }

    #[test]
    fn redirect_count_is_checked_before_deduplication() {
        let body = json!({"origin":"http://localhost","fragment_redirect_uris":vec!["http://localhost/end";33]});
        let errors = Request::parse(None, &body).err().unwrap();
        assert_eq!(errors[0]["type"], "too_long");
        assert_eq!(errors[0]["ctx"]["actual_length"], "33");
    }
}
