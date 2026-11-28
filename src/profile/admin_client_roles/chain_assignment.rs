//! Resolve the selected role group and prepare its membership transaction.
use super::*;
use crate::{chain_settings::Chain, login_http::problem};

#[derive(Clone, Copy)]
pub(super) enum MembershipEdit {
    Grant { delegated: bool },
    Revoke,
}

impl MembershipEdit {
    fn granting(self) -> bool {
        matches!(self, Self::Grant { .. })
    }

    fn no_identity(self) -> Response {
        match self {
            Self::Grant { delegated: true } => problem(
                StatusCode::CONFLICT,
                "user has no IAM identity; an admin must create one before granting roles",
            ),
            Self::Grant { delegated: false } => problem(
                StatusCode::CONFLICT,
                "user has no IAM identity; create one before granting roles",
            ),
            Self::Revoke => revoke::no_identity(),
        }
    }
}

impl Assignment {
    // A missing organization group makes a scoped revoke a successful no-op.
    pub(super) async fn prepare_membership(
        &self,
        pool: &PgPool,
        chain: &Chain,
        edit: MembershipEdit,
    ) -> Result<Option<Response>, sqlx::Error> {
        let inventory = match chain.snapshot().await {
            Ok(groups) => groups,
            Err(error) => return Ok(Some(chain_error(error))),
        };
        let Some(global) = inventory
            .groups
            .into_iter()
            .find(|g| global_key(&self.client, &g.name).as_deref() == Some(&self.key))
        else {
            return Ok(Some(missing_role(&self.client, &self.key)));
        };
        let group = if let Some(org) = self.org {
            if edit.granting() {
                let mut tx = pool.begin().await?;
                if !self.is_member(&mut tx, org).await? {
                    return Ok(Some(grant::not_member()));
                }
                tx.commit().await?;
            }
            let inventory = match chain.snapshot().await {
                Ok(groups) => groups,
                Err(error) => return Ok(Some(chain_error(error))),
            };
            let name = format!("{}@{org}", global.name);
            match inventory.groups.into_iter().find(|g| g.name == name) {
                Some(group) => group.id,
                None if edit.granting() => {
                    return Ok(Some(
                        prepare_scoped_group(pool, chain, &name, &global.description).await?,
                    ));
                }
                None => return Ok(None),
            }
        } else {
            global.id
        };
        self.prepare_linked_membership(pool, chain, group, edit)
            .await
            .map(Some)
    }

    async fn prepare_linked_membership(
        &self,
        pool: &PgPool,
        chain: &Chain,
        group: alloy_primitives::U256,
        edit: MembershipEdit,
    ) -> Result<Response, sqlx::Error> {
        let linked: Option<i32> =
            sqlx::query_scalar("SELECT chain_token_id FROM iam_identities WHERE user_id=$1")
                .bind(self.user)
                .fetch_optional(pool)
                .await?
                .flatten();
        let Some(identity) = linked else {
            return Ok(edit.no_identity());
        };
        let preparation = chain.prepare_role_membership(group, identity, edit.granting());
        let response = match chain
            .with_signer_lock(pool.begin().await?, preparation)
            .await?
        {
            Err(error) => preparation_error(error),
            Ok(_) => problem(
                StatusCode::SERVICE_UNAVAILABLE,
                match edit {
                    MembershipEdit::Grant { .. } => "Blockchain role assignment unavailable",
                    MembershipEdit::Revoke => "Blockchain role revocation unavailable",
                },
            ),
        };
        Ok(response)
    }
}

async fn prepare_scoped_group(
    pool: &PgPool,
    chain: &Chain,
    name: &str,
    description: &str,
) -> Result<Response, sqlx::Error> {
    let preparation = chain.prepare_group_creation(name, Some(description));
    Ok(
        match chain
            .with_signer_lock(pool.begin().await?, preparation)
            .await?
        {
            Ok(_) => problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Blockchain role assignment unavailable",
            ),
            Err(_) => internal(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn scoped_group_preparation_waits_for_other_role_writers() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let chain = Chain::for_health_test("http://localhost".into());
        let mut writer = pool.begin().await.unwrap();
        chain.lock_signer(&mut writer).await.unwrap();
        let scoped = prepare_scoped_group(&pool, &chain, "rp:client:reader@org", "reader");
        tokio::pin!(scoped);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut scoped)
                .await
                .is_err()
        );
        writer.commit().await.unwrap();
        // The test chain has no group contract, so preparation now fails locally.
        let response = tokio::time::timeout(Duration::from_secs(2), scoped)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
