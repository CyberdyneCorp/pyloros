//! The OAuth client-credentials grant.
use super::{Json, Response, SessionOrigin, StatusCode};
use crate::{
    browser_prompt::{quoted_list, quoted_string},
    login_throttle::LoginThrottle,
    signing::SigningIdentity,
};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use std::{collections::BTreeSet, error::Error};
use uuid::Uuid;

pub(super) struct Issuer {
    pool: PgPool,
    signing: SigningIdentity,
    quota: LoginThrottle,
}
pub(super) struct Request<'a> {
    pub grant: &'a str,
    pub client: &'a str,
    pub secret: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub origin: SessionOrigin<'a>,
}
struct Decision {
    error: Option<&'static str>,
    scopes: String,
    response: Response,
}
impl Decision {
    fn refuse(error: &'static str, description: impl Into<String>) -> Self {
        let (status, code) = match error {
            "invalid_client" => (StatusCode::UNAUTHORIZED, error),
            "rate_limited" => (StatusCode::TOO_MANY_REQUESTS, "invalid_request"),
            _ => (StatusCode::BAD_REQUEST, error),
        };
        Self {
            scopes: String::new(),
            error: Some(error),
            response: (
                status,
                Json(json!({"error":code,"error_description":description.into()})),
            )
                .into_response(),
        }
    }
}

impl Issuer {
    pub(super) fn configured(
        pool: PgPool,
        production: bool,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        Ok(
            crate::login_http::signing_identity(production)?.map(|(signing, _)| Self {
                pool,
                signing,
                quota: LoginThrottle::new(60),
            }),
        )
    }
    pub(super) async fn exchange(
        &self,
        req: Request<'_>,
    ) -> Result<Response, Box<dyn Error + Send + Sync>> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();
        let decision = self.decide(&mut tx, &req, now).await?;
        if decision.error.is_none() {
            sqlx::query(
                "UPDATE oauth_clients SET last_used_at=$2,updated_at=now() WHERE client_id=$1",
            )
            .bind(req.client)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("INSERT INTO oauth_token_issuance_log(id,client_id,success,error_code,scopes,audience,ip_address,user_agent,issued_at)
            VALUES($1,$2,$3,$4,$5,$6,$7::text::inet,$8,$9)")
            .bind(Uuid::new_v4()).bind(req.client).bind(decision.error.is_none()).bind(decision.error).bind(decision.scopes).bind(req.audience)
            .bind(req.origin.ip.map(|ip|ip.to_string())).bind(req.origin.user_agent).bind(now).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(decision.response)
    }
    async fn decide(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        req: &Request<'_>,
        now: DateTime<Utc>,
    ) -> Result<Decision, Box<dyn Error + Send + Sync>> {
        if req.grant != "client_credentials" {
            return Ok(Decision::refuse(
                "unsupported_grant_type",
                format!(
                    "grant_type must be 'client_credentials', got {}",
                    quoted_string(req.grant)
                ),
            ));
        }
        let Some(secret) = req.secret.filter(|_| !req.client.is_empty()) else {
            return Ok(Decision::refuse(
                "invalid_client",
                "missing client credentials",
            ));
        };
        let registration = sqlx::query(
            "SELECT active, secret_hash, CASE WHEN previous_secret_expires_at > $2 THEN previous_secret_hash END AS previous,
                    grant_types, allowed_scopes, allowed_audiences, max_token_ttl_s
               FROM oauth_clients WHERE client_id = $1",
        )
        .bind(req.client)
        .bind(now)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(row) = registration else {
            return Ok(Decision::refuse("invalid_client", "unknown client"));
        };
        if !self.quota.allow_client(Some(req.client), None) {
            return Ok(Decision::refuse(
                "rate_limited",
                "token-endpoint quota exceeded for this client",
            ));
        }
        if !crate::client_auth::verify_secret(
            secret,
            row.try_get("secret_hash")?,
            row.try_get("previous")?,
        )
        .await?
        {
            return Ok(Decision::refuse("invalid_client", "bad client secret"));
        }
        if !row.try_get::<bool, _>("active")? {
            return Ok(Decision::refuse("invalid_grant", "client disabled"));
        }
        let grants = row
            .try_get::<Option<&str>, _>("grant_types")?
            .unwrap_or_default();
        if !grants.is_empty() && !grants.split_whitespace().any(|s| s == "client_credentials") {
            return Ok(Decision::refuse(
                "unauthorized_client",
                "client may not use the client_credentials grant",
            ));
        }
        self.issue(req, &row, now)
    }
    fn issue(
        &self,
        req: &Request<'_>,
        row: &PgRow,
        now: DateTime<Utc>,
    ) -> Result<Decision, Box<dyn Error + Send + Sync>> {
        let allowed: BTreeSet<_> = row
            .try_get::<&str, _>("allowed_scopes")?
            .split_whitespace()
            .collect();
        let requested: BTreeSet<_> = req.scope.unwrap_or_default().split_whitespace().collect();
        let scopes = requested.iter().copied().collect::<Vec<_>>().join(" ");
        let extra: Vec<_> = requested.difference(&allowed).copied().collect();
        if !extra.is_empty() {
            return Ok(Decision {
                scopes,
                ..Decision::refuse(
                    "invalid_scope",
                    format!(
                        "scopes not allowed for this client: {}",
                        quoted_list(&extra)
                    ),
                )
            });
        }
        let audiences: Option<sqlx::types::Json<Option<Vec<String>>>> =
            row.try_get("allowed_audiences")?;
        if let (Some(aud), Some(list)) = (req.audience, audiences.and_then(|json| json.0))
            && !list.iter().any(|a| a == aud)
        {
            return Ok(Decision {
                scopes,
                ..Decision::refuse(
                    "invalid_scope",
                    format!(
                        "audience not allowed for this client: {}",
                        quoted_string(aud)
                    ),
                )
            });
        }
        let scopes = if requested.is_empty() {
            allowed.into_iter().collect::<Vec<_>>().join(" ")
        } else {
            scopes
        };
        let ttl: i32 = row.try_get("max_token_ttl_s")?;
        let mut claims = json!({"iss":self.signing.issuer(),"sub":format!("client:{}",req.client),"client_id":req.client,"jti":Uuid::new_v4(),"type":"service","scope":scopes,"iat":now.timestamp(),"exp":now.timestamp()+i64::from(ttl)});
        if let Some(aud) = req.audience {
            claims["aud"] = json!(aud)
        }
        let mut body = json!({"access_token":self.signing.sign(&claims)?,"token_type":"Bearer","expires_in":ttl});
        if !scopes.is_empty() {
            body["scope"] = json!(scopes)
        }
        Ok(Decision {
            scopes,
            error: None,
            response: (
                [("cache-control", "no-store"), ("pragma", "no-cache")],
                Json(body),
            )
                .into_response(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_failed_issuance_log_write_rolls_back_client_use() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE oauth_clients(client_id text,active boolean,secret_hash text,previous_secret_expires_at timestamptz,
            previous_secret_hash text,grant_types text,allowed_scopes text,allowed_audiences jsonb,max_token_ttl_s int,last_used_at timestamptz,updated_at timestamptz);
            CREATE TEMP TABLE oauth_token_issuance_log(id uuid,client_id text,success boolean CHECK (NOT success),error_code text,scopes text,audience text,ip_address inet,user_agent text,issued_at timestamptz);").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO oauth_clients(client_id,active,secret_hash,allowed_scopes,max_token_ttl_s)
            VALUES('app',true,$1,'read',300)").bind("$argon2id$v=19$m=65536,t=3,p=4$jNH6XwvB+F8rJSSklBJCKA$oqK3cymfWAvf2VdVy1kHyMY37eyi7e5vkDc0Oo3IKYY").execute(&pool).await.unwrap();
        let issuer = Issuer {
            pool: pool.clone(),
            signing: SigningIdentity::hmac("issuer".into(), b"fixture").unwrap(),
            quota: LoginThrottle::new(60),
        };
        let request = || Request {
            grant: "client_credentials",
            client: "app",
            secret: Some("test-current"),
            scope: None,
            audience: None,
            origin: SessionOrigin {
                ip: None,
                user_agent: None,
            },
        };
        assert!(issuer.exchange(request()).await.is_err());
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT last_used_at IS NULL FROM oauth_clients")
                .fetch_one(&pool)
                .await
                .unwrap()
        );
        sqlx::query("ALTER TABLE oauth_token_issuance_log DROP CONSTRAINT oauth_token_issuance_log_success_check").execute(&pool).await.unwrap();
        let response = issuer.exchange(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let verifier =
            crate::mfa_challenges::ChallengeVerifier::hmac("issuer", b"fixture").unwrap();
        assert!(
            matches!(verifier.token_for_revocation(body["access_token"].as_str().unwrap()),Ok(crate::token_revocation::VerifiedToken::Service{client,..}) if client=="app")
        );
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT last_used_at IS NOT NULL FROM oauth_clients")
                .fetch_one(&pool)
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM oauth_token_issuance_log WHERE success"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
    }
}
