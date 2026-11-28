//! Resolve the role group and confirm its membership change under the signer lock.
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
    pub(super) async fn change_membership(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        chain: &Chain,
        edit: MembershipEdit,
        state: &Profile,
    ) -> Result<Result<bool, Box<Response>>, sqlx::Error> {
        let group = match self.assignment_group(tx, chain, edit).await? {
            Ok(Some(group)) => group,
            Ok(None) => return Ok(Ok(false)),
            Err(response) => return Ok(Err(response)),
        };
        let token = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT chain_token_id FROM iam_identities WHERE user_id=$1",
        )
        .bind(self.user)
        .fetch_optional(&mut **tx)
        .await?
        .flatten();
        let Some(token) = token else {
            return Ok(Err(Box::new(edit.no_identity())));
        };
        if state.registration.hooks {
            let (event, refusal) = match edit {
                MembershipEdit::Grant { .. } => {
                    ("role_granted", "Role grant hook dispatcher unavailable")
                }
                MembershipEdit::Revoke => (
                    "role_revoked",
                    "Role revocation hook dispatcher unavailable",
                ),
            };
            if !self.queue_hook(tx, event).await? {
                return Ok(Err(Box::new(problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    refusal,
                ))));
            }
        }
        Ok(chain
            .change_role_membership(group, token, edit.granting())
            .await
            .map(|()| true)
            .map_err(|e| Box::new(preparation_error(e))))
    }

    async fn assignment_group(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        chain: &Chain,
        edit: MembershipEdit,
    ) -> Result<Result<Option<alloy_primitives::U256>, Box<Response>>, sqlx::Error> {
        chain.lock_signer(tx).await?;
        let inventory = match chain.snapshot().await {
            Ok(groups) => groups,
            Err(error) => return Ok(Err(Box::new(chain_error(error)))),
        };
        let Some(global) = inventory
            .groups
            .into_iter()
            .find(|g| global_key(&self.client, &g.name).as_deref() == Some(&self.key))
        else {
            return Ok(Err(Box::new(missing_role(&self.client, &self.key))));
        };
        let Some(org) = self.org else {
            return Ok(Ok(Some(global.id)));
        };
        if edit.granting() && !self.is_member(tx, org).await? {
            return Ok(Err(Box::new(grant::not_member())));
        }
        let name = format!("{}@{org}", global.name);
        let inventory = match chain.snapshot().await {
            Ok(groups) => groups,
            Err(error) => return Ok(Err(Box::new(chain_error(error)))),
        };
        if let Some(group) = inventory
            .groups
            .into_iter()
            .find(|group| group.name == name)
        {
            return Ok(Ok(Some(group.id)));
        }
        if !edit.granting() {
            return Ok(Ok(None));
        }
        Ok(chain
            .create_group_entry(&name, Some(&global.description))
            .await
            .map(|entry| Some(entry.id))
            .map_err(|_| Box::new(internal())))
    }
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
        let mut waiting = pool.begin().await.unwrap();
        let assignment = Assignment {
            user: Uuid::new_v4(),
            org: Some(Uuid::new_v4()),
            client: "client".into(),
            key: "reader".into(),
        };
        let scoped = assignment.assignment_group(
            &mut waiting,
            &chain,
            MembershipEdit::Grant { delegated: false },
        );
        tokio::pin!(scoped);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut scoped)
                .await
                .is_err()
        );
        writer.commit().await.unwrap();
        // After the lock is released, catalog discovery reports the missing contracts.
        let response = tokio::time::timeout(Duration::from_secs(2), scoped)
            .await
            .unwrap();
        assert!(matches!(response.unwrap(), Err(error) if !error.status().is_success()));
    }
}
