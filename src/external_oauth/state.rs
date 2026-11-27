//! External OAuth state across the provider round trip.
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub struct ReturnInstructions {
    pub return_mode: String,
    pub frontend_redirect: Option<String>,
    pub cli_port: Option<i32>,
    pub code_challenge: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Pending {
    id: Uuid,
    provider: String,
    pub instructions: ReturnInstructions,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvalidState {
    #[error("state is not a valid identifier")]
    Identifier,
    #[error("state unknown")]
    Unknown,
    #[error("state bound to a different provider")]
    Provider,
    #[error("state already consumed")]
    Consumed,
    #[error("state expired")]
    Expired,
}

impl ReturnInstructions {
    pub(super) async fn issue(
        &self,
        pool: &PgPool,
        provider: &str,
        ttl: i64,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO oauth_states
             (id,provider,return_mode,frontend_redirect,expires_at,cli_port,code_challenge)
             VALUES ($1,$2,$3,$4,clock_timestamp()+$5*interval '1 second',$6,$7)",
        )
        .bind(id)
        .bind(provider)
        .bind(&self.return_mode)
        .bind(&self.frontend_redirect)
        .bind(ttl as f64)
        .bind(self.cli_port)
        .bind(&self.code_challenge)
        .execute(pool)
        .await?;
        Ok(id)
    }
}

impl Pending {
    /// Inspect state before calling the provider. No connection is held during the exchange.
    pub async fn inspect(
        pool: &PgPool,
        raw: &str,
        provider: &str,
    ) -> Result<Result<Self, InvalidState>, sqlx::Error> {
        let Ok(id) = Uuid::parse_str(raw) else {
            return Ok(Err(InvalidState::Identifier));
        };
        let row = sqlx::query(
            "SELECT provider, consumed_at IS NOT NULL AS consumed, expires_at <= clock_timestamp() AS expired,
             return_mode,frontend_redirect,cli_port,code_challenge FROM oauth_states WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        let Some(row) = row else {
            return Ok(Err(InvalidState::Unknown));
        };
        if row.try_get::<&str, _>("provider")? != provider {
            return Ok(Err(InvalidState::Provider));
        }
        if row.try_get("consumed")? {
            return Ok(Err(InvalidState::Consumed));
        }
        if row.try_get("expired")? {
            return Ok(Err(InvalidState::Expired));
        }
        Ok(Ok(Self {
            id,
            provider: provider.to_owned(),
            instructions: ReturnInstructions {
                return_mode: row.try_get("return_mode")?,
                frontend_redirect: row.try_get("frontend_redirect")?,
                cli_port: row.try_get("cli_port")?,
                code_challenge: row.try_get("code_challenge")?,
            },
        }))
    }

    /// Claim the inspected state in the transaction that persists the login result.
    pub async fn claim(&self, tx: &mut Transaction<'_, Postgres>) -> Result<bool, sqlx::Error> {
        let row = &self.instructions;
        let result = sqlx::query(
            "UPDATE oauth_states SET consumed_at=clock_timestamp()
             WHERE id=$1 AND provider=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp()
             AND return_mode=$3 AND frontend_redirect IS NOT DISTINCT FROM $4
             AND cli_port IS NOT DISTINCT FROM $5 AND code_challenge IS NOT DISTINCT FROM $6",
        )
        .bind(self.id)
        .bind(&self.provider)
        .bind(&row.return_mode)
        .bind(&row.frontend_redirect)
        .bind(row.cli_port)
        .bind(&row.code_challenge)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}
