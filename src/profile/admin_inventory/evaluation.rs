//! Explain operator access checks against the selected IAM provider.
use super::*;
use crate::{
    iam_evaluation::{Condition, matches_target},
    login_http::problem,
    request_json::fields,
};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub(super) struct Request {
    identity_id: Uuid,
    action: String,
    resource: String,
    context: HashMap<String, String>,
}
#[derive(Deserialize)]
struct Policy {
    id: Uuid,
    statements: Vec<Statement>,
}
#[derive(Deserialize)]
struct Statement {
    actions: Vec<String>,
    resources: Vec<String>,
    effect: String,
    conditions: Vec<Condition>,
    sid: Option<String>,
}

pub(in crate::profile) async fn evaluate(
    State(state): State<Arc<Profile>>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let doc = match fields::document(&headers, &bytes) {
        Ok(doc) => doc,
        Err(error) => return *error,
    };
    let (mut tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(record) => record,
        Err(error) => return *error,
    };
    let Ok(chain) = admin_client_roles::authority(&state).await else {
        return internal();
    };
    let Some(doc) = doc else {
        return internal();
    };
    let req = match input::evaluation(&doc) {
        Ok(req) => req,
        Err(error) => return *error,
    };
    if let Some(chain) = chain {
        if tx.commit().await.is_err() {
            return internal();
        }
        if let Err(error) = chain.check_user_catalog().await {
            return admin_client_roles::chain_error(error);
        }
        return missing(req.identity_id);
    }
    postgres(&mut tx, &req).await.unwrap_or_else(|_| internal())
}

fn missing(id: Uuid) -> Response {
    problem(StatusCode::NOT_FOUND, &id.to_string())
}

async fn postgres(
    tx: &mut Transaction<'_, Postgres>,
    req: &Request,
) -> Result<Response, sqlx::Error> {
    let id = req.identity_id;
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT status,transfer_mode FROM iam_identities WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((status, mode)) = row else {
        return Ok(missing(id));
    };
    user_identity::validate_identity(&status, &mode)?;
    let mut matched = Vec::new();
    if status != "active" {
        return Ok(decision(
            matched,
            Some(&format!("identity status is {status}")),
        ));
    }
    let direct =
        sqlx::query_scalar("SELECT policy_id FROM iam_identity_policies WHERE identity_id=$1")
            .bind(id)
            .fetch_all(&mut **tx)
            .await?;
    let groups = sqlx::query_scalar("SELECT ARRAY(SELECT policy_id FROM iam_group_policies p WHERE p.group_id=m.group_id) FROM iam_group_members m WHERE m.identity_id=$1")
        .bind(id).fetch_all(&mut **tx).await?;
    let roles = sqlx::query_scalar("SELECT ARRAY(SELECT policy_id FROM iam_role_policies p WHERE p.role_id=s.role_id) FROM iam_role_sessions s WHERE s.identity_id=$1 AND s.active AND s.expiry_at>statement_timestamp()")
        .bind(id).fetch_all(&mut **tx).await?;
    let mut links = Vec::new();
    append_links(&mut links, [direct], "identity");
    append_links(&mut links, groups, "group");
    append_links(&mut links, roles, "role");
    if !evaluate_links(tx, req, &links, &mut matched).await? {
        return Ok(decision(matched, Some("no matching allow")));
    }
    let boundary =
        sqlx::query_scalar("SELECT policy_id FROM iam_permission_boundaries WHERE identity_id=$1")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some(boundary) = boundary {
        let policies = statements::policies(tx, Some(boundary)).await?;
        if let Some(doc) = policies.into_iter().next() {
            let mut effects = Effects::default();
            effects.apply(&policy(doc)?, "boundary", req, &mut matched)?;
            if !effects.allowed() {
                return Ok(decision(matched, Some("denied by permission boundary")));
            }
        }
    }
    Ok(decision(matched, None))
}

fn append_links(
    links: &mut Vec<(Uuid, &'static str)>,
    sets: impl IntoIterator<Item = Vec<Uuid>>,
    source: &'static str,
) {
    links.extend(sets.into_iter().flatten().map(|id| (id, source)));
}

fn decision(matched: Vec<Value>, reason: Option<&str>) -> Response {
    Json(json!({"matched":matched,"decision":if reason.is_none() {"allow"}else{"deny"},"reason":reason})).into_response()
}

fn policy(doc: Value) -> Result<Policy, sqlx::Error> {
    serde_json::from_value(doc).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

async fn evaluate_links(
    tx: &mut Transaction<'_, Postgres>,
    req: &Request,
    links: &[(Uuid, &str)],
    matched: &mut Vec<Value>,
) -> Result<bool, sqlx::Error> {
    let mut ids: Vec<_> = links.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut by_id = HashMap::new();
    for doc in statements::load(tx, Some(&ids)).await? {
        let p = policy(doc)?;
        by_id.insert(p.id, p);
    }
    let mut effects = Effects::default();
    for (id, source) in links {
        if let Some(p) = by_id.get(id) {
            effects.apply(p, source, req, matched)?;
        }
    }
    Ok(effects.allowed())
}

#[derive(Default)]
struct Effects {
    allow: bool,
    deny: bool,
}
impl Effects {
    fn allowed(&self) -> bool {
        self.allow && !self.deny
    }
    fn apply(
        &mut self,
        policy: &Policy,
        source: &str,
        req: &Request,
        matched: &mut Vec<Value>,
    ) -> Result<(), sqlx::Error> {
        for stmt in &policy.statements {
            if stmt.applies(req)? {
                self.allow |= stmt.effect == "allow";
                self.deny |= stmt.effect == "deny";
                matched.push(json!({"policy_id":policy.id,"source":source,"sid":stmt.sid,"effect":stmt.effect}));
            }
        }
        Ok(())
    }
}
impl Statement {
    fn applies(&self, req: &Request) -> Result<bool, sqlx::Error> {
        if !matches_target(&self.actions, &self.resources, &req.action, &req.resource) {
            return Ok(false);
        }
        for condition in &self.conditions {
            if !condition
                .matches(&req.context)
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deny_keeps_ordered_explanations_and_unmatched_targets_skip_conditions() {
        let id = Uuid::new_v4();
        let policy=policy(json!({"id":id,"statements":[
            {"effect":"allow","actions":["read"],"resources":["*"],"conditions":[],"sid":"grant"},
            {"effect":"deny","actions":["write"],"resources":["*"],"conditions":[
                {"operator":"DateTimeGreaterThan","key":"time","value":"2026-01-01"}
            ]},
            {"effect":"deny","actions":["read"],"resources":["*"],"conditions":[],"sid":"restriction"}
        ]})).unwrap();
        let req = Request {
            identity_id: Uuid::new_v4(),
            action: "read".into(),
            resource: "doc".into(),
            context: HashMap::from([("time".into(), "2026-03-01T01:23:00Z".into())]),
        };
        let mut effects = Effects::default();
        let mut matched = Vec::new();
        effects
            .apply(&policy, "identity", &req, &mut matched)
            .unwrap();
        effects.apply(&policy, "group", &req, &mut matched).unwrap();
        assert!(!effects.allowed());
        assert_eq!(
            matched
                .iter()
                .map(|m| (m["source"].as_str().unwrap(), m["sid"].as_str().unwrap()))
                .collect::<Vec<_>>(),
            [
                ("identity", "grant"),
                ("identity", "restriction"),
                ("group", "grant"),
                ("group", "restriction")
            ]
        );
    }
}
