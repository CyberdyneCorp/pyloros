use super::*;
use crate::{
    login_http::problem,
    login_throttle::{LoginThrottle, RateLimited},
    token_http::client_ip,
};
use serde::Serialize;

pub(super) struct Inventory {
    rp: Option<String>,
    quota: LoginThrottle,
}

impl Inventory {
    pub(super) fn configured() -> Result<Self, Box<dyn Error>> {
        let rp = crate::login_methods::passkey_rp(
            env::var("APP_ENV").unwrap_or_else(|_| "dev".into()) == "dev",
        )?;
        let limit = crate::token_runtime::number("PASSKEYS_RATE_LIMIT_PER_MIN", 10)?;
        if !(1..=100).contains(&limit) {
            return Err("invalid PASSKEYS_RATE_LIMIT_PER_MIN".into());
        }
        Ok(Self::new(rp, limit))
    }
    pub(super) fn new(rp: Option<String>, limit: i64) -> Self {
        Self {
            rp,
            quota: LoginThrottle::new(limit),
        }
    }
}

pub(super) async fn list(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let Some(id) = credential(&headers)
        .and_then(|t| state.verify.as_ref()?.read(t))
        .filter(|id| !id.client_bound)
    else {
        return unauthorized();
    };
    let result = inventory(&state, &id, client_ip(&headers, peer.ip(), state.proxies)).await;
    result.unwrap_or_else(|_| {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Passkey inventory unavailable",
        )
    })
}

async fn inventory(
    state: &Profile,
    id: &Identity,
    source: Option<std::net::IpAddr>,
) -> Result<Response, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, id).await? {
        return Ok(unauthorized());
    }
    let Some(session) = id.sid else {
        return Ok(problem(
            StatusCode::UNAUTHORIZED,
            "First-party session required; sign in again",
        ));
    };
    let Some(rp) = &state.passkeys.rp else {
        return Ok(problem(StatusCode::NOT_FOUND, "Passkeys disabled"));
    };
    if !state.passkeys.quota.allow(source) {
        return Ok(RateLimited.into_response());
    }
    let live=sqlx::query_scalar::<_,i32>(
        "SELECT 1 FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2
        AND u.is_active AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND (u.tokens_valid_after IS NULL OR $3>floor(extract(epoch FROM u.tokens_valid_after))::bigint) FOR SHARE OF u,s"
    ).bind(id.user).bind(session).bind(id.iat).fetch_optional(&mut *tx).await?;
    if live.is_none() {
        return Ok(problem(
            StatusCode::UNAUTHORIZED,
            "Invalid passkey ceremony or authentication proof",
        ));
    }
    let rows = metadata(&mut tx, id.user, rp).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(rows)).into_response())
}

#[derive(Serialize)]
struct Record {
    id: Uuid,
    name: String,
    created_at: String,
    last_used_at: Option<String>,
    backup_eligible: bool,
    backed_up: bool,
}

async fn metadata(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    rp: &str,
) -> Result<Vec<Record>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id,name,created_at,last_used_at,backup_eligible,backed_up FROM passkeys
        WHERE user_id=$1 AND rp_id=$2 AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(user)
    .bind(rp)
    .fetch_all(&mut **tx)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(Record {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                created_at: timestamp(row.try_get("created_at")?),
                last_used_at: row
                    .try_get::<Option<DateTime<Utc>>, _>("last_used_at")?
                    .map(timestamp),
                backup_eligible: row.try_get("backup_eligible")?,
                backed_up: row.try_get("backed_up")?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn inventory_is_scoped_to_owner_relying_party_and_active_records() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE passkeys(id uuid,user_id uuid,rp_id text,name text,created_at timestamptz,last_used_at timestamptz,backup_eligible bool,backed_up bool,revoked_at timestamptz)").execute(&mut *tx).await.unwrap();
        let owner = Uuid::new_v4();
        let foreign = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO passkeys VALUES
            ($1,$1,'rp','current',now(),NULL,true,false,NULL),
            ($2,$2,'rp','foreign',now(),NULL,true,false,NULL),
            ($2,$1,'other','other RP',now(),NULL,true,false,NULL),
            ($2,$1,'rp','revoked',now(),NULL,true,false,now())",
        )
        .bind(owner)
        .bind(foreign)
        .execute(&mut *tx)
        .await
        .unwrap();
        let rows = metadata(&mut tx, owner, "rp").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "current");
        assert!(rows[0].last_used_at.is_none());
    }
}
