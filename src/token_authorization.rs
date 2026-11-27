//! Resolve token claims for grants using the selected IAM provider.
use crate::chain_settings::ChainSettings;
use crate::id_tokens::{Assignments, AuthorizationClaims};
use sqlx::{Acquire, Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(crate) fn assignment(name: &str) -> Option<(String, Option<Uuid>)> {
    let body = name.strip_prefix("rp:")?;
    let (token, organization) = match body.split_once('@') {
        Some((token, id)) => (token, Some(organization_id(id)?)),
        None => (body, None),
    };
    let (client, key) = token.rsplit_once(':')?;
    (valid_role_key(key) && !client.is_empty()).then(|| (token.to_owned(), organization))
}

fn organization_id(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value).ok().or_else(|| {
        // Older stored organization identifiers can have noncanonical separators.
        let hex = value
            .strip_prefix("urn:uuid:")
            .unwrap_or(value)
            .trim_matches(|ch| matches!(ch, '{' | '}'))
            .replace('-', "");
        (hex.len() == 32)
            .then(|| Uuid::parse_str(&hex).ok())
            .flatten()
    })
}

pub(crate) fn valid_role_key(key: &str) -> bool {
    let slug = key.strip_suffix('\n').unwrap_or(key);
    let alphanumeric = |b: u8| b.is_ascii_digit() || b.is_ascii_lowercase();
    slug.len() <= 48
        && slug.bytes().next().is_some_and(alphanumeric)
        && slug
            .bytes()
            .all(|b| alphanumeric(b) || matches!(b, b'-' | b'_'))
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
    resolve_with(&ChainSettings::default(), tx, user, client, audience).await
}

pub(crate) async fn resolve_with(
    settings: &ChainSettings,
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    client: &str,
    audience: Option<&str>,
) -> Result<Option<AuthorizationClaims>, sqlx::Error> {
    let Some(roles) = role_buckets(settings, tx, user).await? else {
        return Ok(None);
    };
    let permissions = permissions(tx, &roles, client, audience).await?;
    Ok(Some(AuthorizationClaims {
        roles: assignments(roles),
        permissions: Some(assignments(permissions)),
    }))
}

pub(crate) async fn profile_roles(
    settings: &ChainSettings,
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Option<Assignments>, sqlx::Error> {
    Ok(role_buckets(settings, tx, user).await?.map(assignments))
}

async fn role_buckets(
    settings: &ChainSettings,
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Option<Buckets>, sqlx::Error> {
    let names = match settings.membership_source().await {
        Some(chain) => chain.groups_for(tx, user).await?,
        None => postgres_groups(tx, user).await?,
    };
    let Some(names) = names else {
        return Ok(None);
    };
    project_groups(tx, user, &names).await.map(Some)
}

async fn postgres_groups(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Option<Vec<String>>, sqlx::Error> {
    let mut lookup = tx.begin().await?;
    let names = stored_groups(&mut lookup, user).await;
    match names {
        Ok(names) => {
            lookup.commit().await?;
            Ok(names)
        }
        Err(_) => {
            lookup.rollback().await?;
            Ok(None)
        }
    }
}

pub(crate) async fn stored_groups(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Option<Vec<String>>, sqlx::Error> {
    sqlx::query_scalar::<_, Vec<String>>(
        "SELECT ARRAY(SELECT g.name FROM iam_group_members m JOIN iam_groups g ON g.id=m.group_id
                      WHERE m.identity_id=(SELECT id FROM iam_identities WHERE user_id=u.id))
         FROM users u WHERE u.id=$1",
    )
    .bind(user)
    .fetch_optional(&mut **tx)
    .await
}

async fn project_groups(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    names: &[String],
) -> Result<Buckets, sqlx::Error> {
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
    Ok(roles)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn provider_groups_are_restricted_to_active_memberships() -> sqlx::Result<()> {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE organizations(id uuid, is_active boolean);
            CREATE TEMP TABLE user_organizations(user_id uuid, organization_id uuid);",
        )
        .execute(&mut *tx)
        .await?;
        let user = Uuid::new_v4();
        let member = Uuid::new_v4();
        let disabled = Uuid::new_v4();
        let other = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations VALUES ($1,true),($2,false),($3,true)")
            .bind(member)
            .bind(disabled)
            .bind(other)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO user_organizations VALUES ($1,$2),($1,$3),($4,$5)")
            .bind(user)
            .bind(member)
            .bind(disabled)
            .bind(Uuid::new_v4())
            .bind(other)
            .execute(&mut *tx)
            .await?;
        let groups = vec![
            "rp:app:reader".into(),
            format!("rp:app:owner@{member}"),
            format!("rp:app:owner@{disabled}"),
            format!("rp:app:owner@{other}"),
        ];
        let roles = assignments(project_groups(&mut tx, user, &groups).await?);
        assert_eq!(roles.global, ["app:reader"]);
        assert_eq!(
            roles.organizations,
            BTreeMap::from([(member.to_string(), vec!["app:owner".into()])])
        );
        assert!(project_groups(&mut tx, user, &[]).await?.is_empty());
        Ok(())
    }
}
