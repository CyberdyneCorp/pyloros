//! User profile authentication and projection for the PostgreSQL IAM deployment.
mod edit;
mod enrollment;
mod logout_all;
mod password_change;
mod totp;
use crate::{config, token_authorization};
use axum::extract::{ConnectInfo, Request};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use chrono::{DateTime, SecondsFormat, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use std::net::SocketAddr;
use std::{env, error::Error, sync::Arc};
use uuid::Uuid;

struct Verifier {
    key: DecodingKey,
    validation: Validation,
}

impl Verifier {
    fn configured(production: bool) -> Result<Option<Self>, Box<dyn Error>> {
        let public = config::pem("JWT_PUBLIC_KEY_PATH", "JWT_PUBLIC_KEY")?;
        let alg = env::var("JWT_ALGORITHM").unwrap_or_else(|_| {
            if public.is_some() {
                "RS256".into()
            } else {
                "HS256".into()
            }
        });
        let (alg, key) = match alg.as_str() {
            "RS256" => {
                let Some(pem) = public else { return Ok(None) };
                (Algorithm::RS256, DecodingKey::from_rsa_pem(pem.as_bytes())?)
            }
            "HS256" => {
                let Ok(secret) = env::var("JWT_SECRET_KEY") else {
                    return Ok(None);
                };
                if secret.is_empty() || (production && secret.len() < 32) {
                    return Err("invalid JWT_SECRET_KEY for profile verification".into());
                }
                (
                    Algorithm::HS256,
                    DecodingKey::from_secret(secret.as_bytes()),
                )
            }
            _ => return Err("unsupported access-token algorithm".into()),
        };
        let issuer = env::var("OIDC_ISSUER")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|oidc| oidc.trim_end_matches('/').to_owned())
            .or_else(|| env::var("JWT_ISSUER").ok())
            .unwrap_or_else(|| "cyberdyne-auth".into());
        Ok(Some(Self::new(alg, key, &issuer)))
    }

    fn new(alg: Algorithm, key: DecodingKey, issuer: &str) -> Self {
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.leeway = 0;
        validation.validate_aud = false;
        validation.validate_nbf = true;
        Self { key, validation }
    }

    fn read(&self, raw: &str) -> Option<Identity> {
        let claims = decode::<Claims>(raw, &self.key, &self.validation)
            .ok()?
            .claims;
        if claims.kind != "access"
            || claims
                .client_id
                .as_ref()
                .is_some_and(|id| id.starts_with("dcr_"))
        {
            return None;
        }
        Some(Identity {
            user: claims.sub.parse().ok()?,
            jti: claims.jti.parse().ok()?,
            sid: match claims.sid {
                Some(s) => Some(s.parse().ok()?),
                None => None,
            },
            iat: claims.iat,
            client_bound: claims.client_id.is_some(),
        })
    }
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    jti: String,
    sid: Option<String>,
    iat: Option<i64>,
    client_id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
}
struct Identity {
    client_bound: bool,
    user: Uuid,
    jti: Uuid,
    sid: Option<Uuid>,
    iat: Option<i64>,
}

async fn revoked(tx: &mut Transaction<'_, Postgres>, id: &Identity) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM users WHERE id=$1)
        OR EXISTS(SELECT 1 FROM users WHERE id=$1 AND $2 <= floor(extract(epoch FROM tokens_valid_after))::bigint)
        OR EXISTS(SELECT 1 FROM revoked_tokens WHERE jti=$3)
        OR EXISTS(SELECT 1 FROM sessions WHERE id=$4 AND revoked_at IS NOT NULL)")
        .bind(id.user).bind(id.iat).bind(id.jti).bind(id.sid).fetch_one(&mut **tx).await
}

struct Profile {
    scheme: crate::passwords::PasswordScheme,
    factor: Option<crate::enrolled_factor::FactorVerifier>,
    mfa_issuer: String,
    cookies: crate::session_cookies::SessionCookies,
    proxies: usize,
    pool: PgPool,
    verify: Option<Verifier>,
    enforce: bool,
    admins: Vec<String>,
    production: bool,
}

pub fn routes(pool: PgPool, production: bool) -> Result<Router, Box<dyn Error>> {
    let state = Profile {
        scheme: env::var("PASSWORD_SCHEME")
            .unwrap_or_else(|_| "argon2".into())
            .parse()?,
        factor: env::var("MASTER_KEY")
            .ok()
            .map(|key| crate::enrolled_factor::FactorVerifier::new(&key))
            .transpose()?,
        mfa_issuer: env::var("MFA_ISSUER").unwrap_or_else(|_| "Cyberdyne Auth".into()),
        cookies: crate::session_cookies::SessionCookies::configured(production)?,
        proxies: env::var("TRUSTED_PROXY_COUNT")
            .unwrap_or_else(|_| "0".into())
            .parse()?,
        pool,
        verify: Verifier::configured(production)?,
        enforce: config::flag("ENFORCE_TOKEN_REVOCATION")?,
        admins: config::admin_emails()?,
        production,
    };
    Ok(Router::new()
        .route("/api/v1/users/me", any(current))
        .route("/api/v1/auth/mfa/status", any(enrollment::handle))
        .route("/api/v1/auth/mfa/totp/setup", any(totp::setup))
        .route("/api/v1/auth/mfa/totp/enable", any(totp::enable))
        .route("/api/v1/auth/mfa/totp/recovery-codes", any(totp::rotate))
        .route("/api/v1/auth/mfa/totp/disable", any(totp::disable))
        .route("/api/v1/auth/password/change", any(password_change::handle))
        .route("/api/v1/auth/logout-all", any(logout_all::handle))
        .route("/api/v1/users/me/entitlements", any(entitlements))
        .with_state(Arc::new(state)))
}

fn credential(headers: &HeaderMap) -> Option<&str> {
    crate::csrf::bearer(headers)
        .or_else(|| crate::csrf::cookie(headers, crate::session_cookies::ACCESS))
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED,[(header::WWW_AUTHENTICATE,"Bearer, Cookie name=\"access_token\"")],
        Json(json!({"type":"about:blank","status":401,"title":"Not authenticated","detail":"Not authenticated"}))).into_response()
}

enum View {
    Enrollment,
    Profile,
    Entitlements,
}

async fn current(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() == Method::PATCH {
        return edit::handle(&state, peer.ip(), req).await;
    }
    serve(&state, req.method().clone(), req.headers(), View::Profile).await
}

async fn entitlements(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    serve(&state, method, &headers, View::Entitlements).await
}

async fn serve(state: &Profile, method: Method, headers: &HeaderMap, view: View) -> Response {
    if method != Method::GET {
        return (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW,"GET")],
            Json(json!({"type":"about:blank","title":"Method Not Allowed","detail":"Method Not Allowed","status":405}))).into_response();
    }
    let Some(id) = credential(headers).and_then(|raw| state.verify.as_ref()?.read(raw)) else {
        return unauthorized();
    };
    if matches!(view, View::Enrollment) && id.client_bound {
        return unauthorized();
    }
    match load(state, &id, view).await {
        Ok(result) => result,
        Err(_) => internal(),
    }
}

fn internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
    )
        .into_response()
}

async fn load(state: &Profile, id: &Identity, view: View) -> Result<Response, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, id).await? {
        return Ok(unauthorized());
    }
    if matches!(view, View::Enrollment) {
        return enrollment::read(&mut tx, id.user).await;
    }
    if matches!(view, View::Entitlements) {
        let tokens =
            sqlx::query_scalar::<_, Vec<String>>(include_str!("effective_entitlements.sql"))
                .bind(id.user)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        return Ok(Json(json!({"entitlements":tokens})).into_response());
    }
    let result = project(state, &mut tx, id.user, true).await?;
    tx.commit().await?;
    Ok(result)
}

async fn project(
    state: &Profile,
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    with_roles: bool,
) -> Result<Response, sqlx::Error> {
    let row = sqlx::query_as::<_, (Value, DateTime<Utc>)>(concat!(
        "WITH effective AS (",
        include_str!("effective_entitlements.sql"),
        ") ",
        include_str!("profile.sql")
    ))
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((mut doc, created)) = row else {
        return Ok((StatusCode::NOT_FOUND,Json(json!({"type":"about:blank","status":404,"title":"User not found","detail":"User not found"}))).into_response());
    };
    let precision = if created.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    doc["created_at"] = json!(created.to_rfc3339_opts(precision, true));
    doc["is_admin"] = json!(config::effective_admin(
        doc["is_admin"] == true,
        doc["email"].as_str(),
        doc["is_email_verified"] == true,
        state.production,
        &state.admins
    ));
    let roles = if with_roles {
        token_authorization::profile_roles(tx, user).await?
    } else {
        None
    };
    doc["roles"] = json!(roles.as_ref().map(|r| &r.global));
    doc["org_roles"] = json!(roles.as_ref().map(|r| &r.organizations));
    Ok(Json(doc).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; run just test-db"]
    async fn effective_grants_follow_the_active_primary_organization() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE users (id uuid, organization_id uuid);
             CREATE TEMP TABLE organizations (id uuid, is_active boolean);
             CREATE TEMP TABLE entitlements (user_id uuid, organization_id uuid, product_key text,
                 plan text, status text, expires_at timestamptz);",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let user = Uuid::new_v4();
        let org = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES ($1,$2)")
            .bind(user)
            .bind(org)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO organizations VALUES ($1,true)")
            .bind(org)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO entitlements VALUES
            ($1,NULL,'docs','pro','active',NULL),(NULL,$2,'docs','pro','active',NULL),
            (NULL,$2,'mail',NULL,'active',NULL),($1,NULL,'old',NULL,'active',now()),
            ($1,NULL,'removed',NULL,'revoked',NULL)",
        )
        .bind(user)
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
        let query = include_str!("effective_entitlements.sql");
        let tokens = sqlx::query_scalar::<_, Vec<String>>(query)
            .bind(user)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(tokens, ["docs:pro", "mail"]);
        sqlx::query("UPDATE organizations SET is_active=false")
            .execute(&mut *tx)
            .await
            .unwrap();
        let tokens = sqlx::query_scalar::<_, Vec<String>>(query)
            .bind(user)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(tokens, ["docs:pro"]);
    }

    #[test]
    fn only_trusted_user_access_credentials_identify_the_profile() {
        use jsonwebtoken::{EncodingKey, Header, encode};
        let secret = b"profile-test-only";
        let verifier = Verifier::new(Algorithm::HS256, DecodingKey::from_secret(secret), "issuer");
        let user = Uuid::new_v4();
        let base = json!({
            "sub":user.to_string(),"iss":"issuer","exp":Utc::now().timestamp()+300,
            "jti":Uuid::new_v4().to_string(),"type":"access","client_id":"registered",
            "aud":"https://resource.example"
        });
        let sign = |claims: &Value, key: &[u8]| {
            encode(&Header::default(), claims, &EncodingKey::from_secret(key)).unwrap()
        };
        assert_eq!(verifier.read(&sign(&base, secret)).unwrap().user, user);
        assert!(verifier.read(&sign(&base, b"unknown-test-key")).is_none());
        for (field, value) in [
            ("iss", json!("other")),
            ("exp", json!(1)),
            ("type", json!("refresh")),
            ("client_id", json!("dcr_test")),
        ] {
            let mut claims = base.clone();
            claims[field] = value;
            assert!(verifier.read(&sign(&claims, secret)).is_none());
        }
    }

    #[test]
    fn explicit_bearer_wins_and_other_schemes_use_the_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "csrf=example; access_token=cookie".parse().unwrap(),
        );
        headers.insert(header::AUTHORIZATION, "bEaReR explicit".parse().unwrap());
        assert_eq!(credential(&headers), Some("explicit"));
        headers.insert(header::AUTHORIZATION, "Basic unrelated".parse().unwrap());
        assert_eq!(credential(&headers), Some("cookie"));
    }
}
