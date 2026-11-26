//! Resolve token claims for grants using PostgreSQL IAM.
use crate::id_tokens::{Assignments, AuthorizationClaims};
use sqlx::{Acquire, Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

fn assignment(name: &str) -> Option<(String, Option<Uuid>)> {
    let body = name.strip_prefix("rp:")?;
    let (token, organization) = match body.split_once('@') {
        Some((token, id)) => (token, Some(Uuid::parse_str(id).ok()?)),
        None => (body, None),
    };
    let (client, key) = token.rsplit_once(':')?;
    let valid = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if client.is_empty()
        || key.len() > 48
        || !valid(*key.as_bytes().first()?)
        || !key.bytes().all(|b| valid(b) || matches!(b, b'-' | b'_'))
    {
        return None;
    }
    Some((token.to_owned(), organization))
}

type Buckets = BTreeMap<Option<Uuid>, BTreeSet<String>>;

fn assignments(mut buckets: Buckets) -> Assignments {
    Assignments {
        global: buckets
            .remove(&None)
            .unwrap_or_default()
            .into_iter()
            .collect(),
        organizations: buckets
            .into_iter()
            .filter_map(|(org, values)| Some((org?.to_string(), values.into_iter().collect())))
            .collect(),
    }
}

pub async fn resolve(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    client: &str,
    audience: Option<&str>,
) -> Result<Option<AuthorizationClaims>, sqlx::Error> {
    let Some(roles) = role_buckets(tx, user).await? else {
        return Ok(None);
    };
    let permissions = permissions(tx, &roles, client, audience).await?;
    Ok(Some(AuthorizationClaims {
        roles: assignments(roles),
        permissions: Some(assignments(permissions)),
    }))
}

pub(crate) async fn profile_roles(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Option<Assignments>, sqlx::Error> {
    Ok(role_buckets(tx, user).await?.map(assignments))
}

async fn role_buckets(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Option<Buckets>, sqlx::Error> {
    let mut lookup = tx.begin().await?;
    let names = sqlx::query_scalar::<_, Vec<String>>(
        "SELECT ARRAY(SELECT g.name FROM iam_group_members m JOIN iam_groups g ON g.id=m.group_id
                      WHERE m.identity_id=(SELECT id FROM iam_identities WHERE user_id=u.id))
         FROM users u WHERE u.id=$1",
    )
    .bind(user)
    .fetch_one(&mut *lookup)
    .await;
    let names = match names {
        Ok(names) => {
            lookup.commit().await?;
            names
        }
        Err(_) => {
            lookup.rollback().await?;
            return Ok(None);
        }
    };
    let refs: Vec<_> = names.iter().filter_map(|name| assignment(name)).collect();
    let mut active = BTreeSet::new();
    if refs.iter().any(|(_, org)| org.is_some()) {
        let memberships = sqlx::query_scalar::<_, Uuid>(
            "SELECT o.id FROM organizations o JOIN user_organizations m ON m.organization_id=o.id
             WHERE m.user_id=$1 AND o.is_active",
        )
        .bind(user)
        .fetch_all(&mut **tx)
        .await?;
        active.extend(memberships);
    }
    let mut roles = Buckets::new();
    for (token, org) in refs {
        if org.is_none_or(|id| active.contains(&id)) {
            roles.entry(org).or_default().insert(token);
        }
    }
    Ok(Some(roles))
}

async fn permissions(
    tx: &mut Transaction<'_, Postgres>,
    roles: &Buckets,
    client: &str,
    audience: Option<&str>,
) -> Result<Buckets, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT client_id || ':' || role_key, permission_key FROM client_role_permissions
         WHERE client_id=$1 OR client_id IN (SELECT client_id FROM oauth_clients
             WHERE active AND registration_source='admin' AND access_token_audience=$2)",
    )
    .bind(client)
    .bind(audience)
    .fetch_all(&mut **tx)
    .await?;
    let mut mappings = BTreeMap::<String, Vec<String>>::new();
    for (role, permission) in rows {
        mappings.entry(role).or_default().push(permission);
    }
    let mut result = Buckets::new();
    for (org, tokens) in roles {
        let keys: BTreeSet<_> = tokens
            .iter()
            .filter_map(|token| mappings.get(token))
            .flatten()
            .cloned()
            .collect();
        if !keys.is_empty() {
            result.insert(*org, keys);
        }
    }
    Ok(result)
}
