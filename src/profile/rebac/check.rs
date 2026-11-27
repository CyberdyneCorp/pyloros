//! Resolve one permission against a consistent view of a client's graph.
use super::*;
use model::{Model, Proof};
use std::collections::{HashSet, VecDeque};

const MAX_DEPTH: usize = 16;
const WORK_LIMIT: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::profile) struct Check {
    user_id: Uuid,
    object: ObjectRef,
    permission: String,
}

fn unavailable() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "Relationship decision unavailable",
    )
}

pub(in crate::profile) async fn check(
    State(state): State<Arc<Profile>>,
    headers: HeaderMap,
    Json(request): Json<Check>,
) -> Response {
    let (client, owner) = match caller(&state, &headers, "rebac:check").await {
        Ok(caller) => caller,
        Err(error) if error.status().is_server_error() => return unavailable(),
        Err(error) => return *error,
    };
    if !request.object.valid() || !model::name(&request.permission) {
        return problem(StatusCode::UNPROCESSABLE_ENTITY, "Invalid permission check");
    }
    let mut response = request
        .evaluate(&state.pool, &client, owner)
        .await
        .unwrap_or_else(|_| unavailable());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

fn decision(allowed: bool) -> Response {
    Json(json!({"allowed":allowed})).into_response()
}

impl Check {
    async fn evaluate(&self, pool: &PgPool, client: &str, owner: Uuid) -> sqlx::Result<Response> {
        let mut tx = pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let (primary, granted): (bool,bool) = sqlx::query_as(
            "SELECT NOT pg_is_in_recovery(), EXISTS(SELECT 1 FROM oauth_clients WHERE id=$1 AND client_id=$2
             AND active AND registration_source='admin' AND client_type='confidential'
             AND 'rebac:check'=ANY(regexp_split_to_array(allowed_scopes,'[[:space:]]+')))",
        ).bind(owner).bind(client).fetch_one(&mut *tx).await?;
        if !primary {
            return Ok(unavailable());
        }
        if !granted {
            return Ok(problem(
                StatusCode::FORBIDDEN,
                "Relationship check grant required",
            ));
        }
        let stored: Option<sqlx::types::Json<Model>> =
            sqlx::query_scalar("SELECT model FROM pyloros_relationship_models WHERE client_id=$1")
                .bind(owner)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(sqlx::types::Json(model)) = stored else {
            return Ok(problem(
                StatusCode::CONFLICT,
                "Install a relationship model first",
            ));
        };
        if model.validate().is_err() {
            return Ok(unavailable());
        }
        if model.rules(&self.object.kind, &self.permission).is_none() {
            return Ok(problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unknown object type or permission",
            ));
        }
        let active: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND is_active)")
                .bind(self.user_id)
                .fetch_one(&mut *tx)
                .await?;
        if !active {
            return Ok(decision(false));
        }
        let root = Node {
            kind: self.object.kind.clone(),
            id: self.object.id.clone(),
            permission: self.permission.clone(),
        };
        let result = Search::new(root)
            .run(&mut tx, &model, owner, self.user_id)
            .await?;
        tx.commit().await?;
        Ok(result.map_or_else(unavailable, decision))
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct Node {
    kind: String,
    id: String,
    permission: String,
}

struct Search {
    queue: VecDeque<(Node, usize)>,
    visited: HashSet<Node>,
    remaining: usize,
    incomplete: bool,
}

impl Search {
    fn new(root: Node) -> Self {
        Self {
            queue: VecDeque::from([(root.clone(), 0)]),
            visited: HashSet::from([root]),
            remaining: WORK_LIMIT,
            incomplete: false,
        }
    }
    async fn run(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        model: &Model,
        owner: Uuid,
        user: Uuid,
    ) -> sqlx::Result<Option<bool>> {
        while let Some((node, depth)) = self.queue.pop_front() {
            let Some(rules) = model.rules(&node.kind, &node.permission) else {
                return Ok(None);
            };
            let count = rules.len().min(self.remaining);
            self.incomplete |= count < rules.len();
            let rules = &rules[..count];
            self.remaining -= count;
            if node.direct(tx, owner, user, rules).await? {
                return Ok(Some(true));
            }
            for rule in rules {
                if let Proof::Inherited { via, permission } = rule {
                    let rows = node
                        .destinations(tx, owner, via, self.remaining + 1)
                        .await?;
                    self.enqueue(rows, model, &node.kind, via, permission, depth + 1);
                }
            }
        }
        Ok((!self.incomplete).then_some(false))
    }

    fn enqueue(
        &mut self,
        rows: Vec<(String, String)>,
        model: &Model,
        kind: &str,
        via: &str,
        permission: &str,
        depth: usize,
    ) {
        if rows.len() > self.remaining {
            self.incomplete = true;
        }
        for (target, id) in rows.into_iter().take(self.remaining) {
            self.remaining -= 1;
            if target == "user" || !model.accepts(kind, via, &target) {
                continue;
            }
            let node = Node {
                kind: target,
                id,
                permission: permission.to_owned(),
            };
            if self.visited.insert(node.clone()) {
                if depth > MAX_DEPTH {
                    self.incomplete = true;
                } else {
                    self.queue.push_back((node, depth));
                }
            }
        }
    }
}

impl Node {
    async fn direct(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: Uuid,
        user: Uuid,
        rules: &[Proof],
    ) -> sqlx::Result<bool> {
        let relations: Vec<&str> = rules
            .iter()
            .filter_map(|rule| match rule {
                Proof::Direct { relation } => Some(relation.as_str()),
                _ => None,
            })
            .collect();
        if relations.is_empty() {
            return Ok(false);
        }
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pyloros_user_relationships WHERE client_id=$1
            AND object_type=$2 AND object_id=$3 AND relation=ANY($4) AND user_id=$5)",
        )
        .bind(owner)
        .bind(&self.kind)
        .bind(&self.id)
        .bind(relations)
        .bind(user)
        .fetch_one(&mut **tx)
        .await
    }
    async fn destinations(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: Uuid,
        via: &str,
        limit: usize,
    ) -> sqlx::Result<Vec<(String, String)>> {
        sqlx::query_as("SELECT subject_type,subject_id FROM pyloros_object_relationships WHERE client_id=$1
            AND object_type=$2 AND object_id=$3 AND relation=$4 ORDER BY subject_type,subject_id LIMIT $5")
            .bind(owner).bind(&self.kind).bind(&self.id).bind(via).bind(limit as i64).fetch_all(&mut **tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_cycle_can_reach_a_grant_and_denies_after_the_last_path_is_removed()
    -> sqlx::Result<()> {
        let pool = sqlx::PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("CREATE TEMP TABLE pyloros_user_relationships(client_id uuid,object_type text,object_id text,relation text,user_id uuid);
            CREATE TEMP TABLE pyloros_object_relationships(client_id uuid,object_type text,object_id text,relation text,subject_type text,subject_id text);")
            .execute(&mut *tx).await?;
        let owner = Uuid::new_v4();
        let user = Uuid::new_v4();
        let model: Model = serde_json::from_value(
            json!({"types":{"file":{"relations":{"parent":["file"],"viewer":["user"]},
            "permissions":{"read":[{"via":"parent","permission":"read"},{"relation":"viewer"}]}}}}),
        )
        .unwrap();
        let search = || {
            Search::new(Node {
                kind: "file".into(),
                id: "x".into(),
                permission: "read".into(),
            })
        };
        sqlx::query("INSERT INTO pyloros_object_relationships VALUES($1,'file','x','parent','file','x'),($1,'file','x','parent','file','y')")
            .bind(owner).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO pyloros_user_relationships VALUES($1,'file','y','viewer',$2)")
            .bind(owner)
            .bind(user)
            .execute(&mut *tx)
            .await?;
        assert_eq!(
            search().run(&mut tx, &model, owner, user).await?,
            Some(true)
        );
        assert_eq!(
            search().run(&mut tx, &model, Uuid::new_v4(), user).await?,
            Some(false)
        );
        let mut limited = search();
        limited.remaining = 2;
        assert_eq!(limited.run(&mut tx, &model, owner, user).await?, None);
        sqlx::query("DELETE FROM pyloros_user_relationships")
            .execute(&mut *tx)
            .await?;
        assert_eq!(
            search().run(&mut tx, &model, owner, user).await?,
            Some(false)
        );
        tx.rollback().await
    }
}
