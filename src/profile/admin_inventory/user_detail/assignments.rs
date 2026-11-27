//! Project the IAM detail for a single user from the selected provider.
use super::*;
fn empty() -> Value {
    json!({"identity":null,"policies":[],"groups":[],"roles":[],"boundary_policy":null})
}

pub(super) async fn remote(
    mut tx: Transaction<'_, Postgres>,
    chain: &Chain,
    user: Uuid,
) -> Result<Response, sqlx::Error> {
    let token = linked_token(&mut tx, user).await?;
    tx.commit().await?;
    if token.is_some()
        && let Err(error) = chain.check_user_catalog().await
    {
        return Ok(admin_client_roles::chain_error(error));
    }
    Ok(Json(empty()).into_response())
}

pub(in crate::profile) async fn linked_token(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Option<i32>, sqlx::Error> {
    let record = sqlx::query_as::<_, (Option<i32>, String, String)>(
        "SELECT chain_token_id,status,transfer_mode FROM iam_identities WHERE user_id=$1",
    )
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((token, status, mode)) = record else {
        return Ok(None);
    };
    user_identity::validate_identity(&status, &mode)?;
    Ok(token)
}

#[derive(Default, serde::Serialize)]
pub(in crate::profile) struct StoredView {
    identity: Option<Value>,
    groups: Vec<Value>,
    roles: Vec<Value>,
    policies: Vec<Value>,
    boundary_policy: Option<Value>,
}

impl StoredView {
    pub(in crate::profile) fn group_names(self) -> Vec<String> {
        self.groups
            .into_iter()
            .map(|group| {
                group["name"]
                    .as_str()
                    .expect("group name selected from PostgreSQL")
                    .to_owned()
            })
            .collect()
    }
}

pub(in crate::profile) async fn postgres(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<StoredView, sqlx::Error> {
    let Some((id, identity)) =
        user_identity::details(tx, user_identity::Lookup::User(user)).await?
    else {
        return Ok(StoredView::default());
    };
    let mut doc = StoredView {
        identity: Some(identity),
        ..Default::default()
    };
    doc.groups=dated(sqlx::query_as(
        "SELECT jsonb_build_object('id',g.id,'name',g.name,'description',g.description,'is_active',g.is_active,
         'chain_group_id',g.chain_group_id,'policy_ids','[]'::jsonb,'member_count',(SELECT count(*) FROM iam_group_members m WHERE m.group_id=g.id)),g.created_at
         FROM iam_group_members m JOIN iam_groups g ON g.id=m.group_id WHERE m.identity_id=$1"
    ).bind(id).fetch_all(&mut **tx).await?);
    let roles: Vec<Uuid> = sqlx::query_scalar(
        "SELECT role_id FROM iam_role_sessions
        WHERE identity_id=$1 AND active AND expiry_at>statement_timestamp()",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    if !roles.is_empty() {
        doc.roles=dated(sqlx::query_as(
            "SELECT jsonb_build_object('id',r.id,'name',r.name,'description',r.description,'max_session_duration_s',r.max_session_duration_s,
             'is_active',r.is_active,'chain_role_id',r.chain_role_id),r.created_at
             FROM unnest($1::uuid[]) WITH ORDINALITY requested(id,position)
             JOIN iam_roles r ON r.id=requested.id ORDER BY requested.position"
        ).bind(&roles).fetch_all(&mut **tx).await?);
    }
    let links = sqlx::query_as::<_, (Uuid, bool)>(
        "SELECT policy_id,false FROM iam_identity_policies WHERE identity_id=$1
        UNION ALL SELECT policy_id,true FROM iam_permission_boundaries WHERE identity_id=$1",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    if links.is_empty() {
        return Ok(doc);
    }
    let ids: Vec<_> = links.iter().map(|(id, _)| *id).collect();
    let mut policies = statements::load(tx, Some(&ids))
        .await?
        .into_iter()
        .peekable();
    let mut direct = Vec::new();
    for (id, boundary) in links {
        // A concurrently deleted policy can disappear between reads.
        if policies.peek().is_some_and(|p| p["id"] == id.to_string()) {
            let value = policies.next().expect("peeked policy");
            if boundary {
                doc.boundary_policy = Some(value);
            } else {
                direct.push(value);
            }
        }
    }
    doc.policies = direct;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn group_reads_distinguish_missing_identity_from_incomplete_iam_storage()
    -> sqlx::Result<()> {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql("SET LOCAL search_path TO pg_temp;
            CREATE TEMP TABLE iam_identities(id uuid,user_id uuid,status text,transfer_mode text,
                chain_token_id int,owner_address text,public_key text,email text,metadata_uri text,created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE iam_groups(id uuid,name text,description text,is_active boolean,chain_group_id int,created_at timestamptz);
            CREATE TEMP TABLE iam_group_members(group_id uuid,identity_id uuid);
            CREATE TEMP TABLE iam_role_sessions(identity_id uuid,role_id uuid,active boolean,expiry_at timestamptz);
            CREATE TEMP TABLE iam_identity_policies(identity_id uuid,policy_id uuid);
            CREATE TEMP TABLE iam_permission_boundaries(identity_id uuid,policy_id uuid);")
            .execute(&mut *tx).await?;
        let user = Uuid::new_v4();
        assert!(postgres(&mut tx, user).await?.group_names().is_empty());
        sqlx::query("INSERT INTO iam_identities(id,user_id,status,transfer_mode) VALUES($1,$2,'active','soulbound')")
            .bind(Uuid::new_v4()).bind(user).execute(&mut *tx).await?;
        assert!(postgres(&mut tx, user).await?.group_names().is_empty());
        sqlx::query("ALTER TABLE iam_role_sessions RENAME TO unavailable_sessions")
            .execute(&mut *tx)
            .await?;
        assert!(postgres(&mut tx, user).await.is_err());
        Ok(())
    }
}
