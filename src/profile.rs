//! User profile authentication and projection for the PostgreSQL IAM deployment.
mod admin_client_roles;
mod admin_clients;
mod admin_fields;
mod admin_inventory;
mod admin_mfa;
mod admin_organizations;
mod audit_directory;
mod event_time;
mod project_usage;
pub(crate) use admin_organizations::normalized_storage;
mod admin_password;
mod admin_permissions;
mod admin_role;
mod admin_sessions;
mod admin_users;
mod admin_wallet;
mod administrator;
mod analytics;
mod apple;
mod auth_policy;
mod billing_grants;
mod blockchain;
mod datetime;
mod delegated;
mod edit;
mod email_verification;
mod entitlement_reports;
mod erasure;
mod google_play;
mod org_directory;
mod rebac;
mod registries;
mod store_products;
mod stripe_checkout;
mod stripe_events;
mod subject_export;
mod subject_identifiers;
pub(crate) use email_verification::verify_account;
mod enrollment;
mod logout_all;
pub(crate) mod passkeys;
pub use passkeys::limit_passkey_body;
mod password_change;
mod password_reset;
mod provisioning;
mod registration;
pub(crate) use registration::enqueue_webhooks;
mod hook_inventory;
mod totp;
mod update_input;
mod userinfo;
mod wallet_challenge;
mod wallet_export;
mod wasm_hooks;
pub use wasm_hooks::ComponentHookWorker;
pub use wasm_hooks::ComponentHookWorker as EntitlementHookWorker;
pub use wasm_hooks::ComponentHookWorker as StoreHookWorker;
pub(crate) use wasm_hooks::delivery::logged_in;
mod webhook_history;
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

pub(crate) struct Verifier {
    key: DecodingKey,
    validation: Validation,
}

impl Verifier {
    pub(crate) fn configured(production: bool) -> Result<Option<Self>, Box<dyn Error>> {
        use crate::config::SigningAlgorithm;
        let (alg, key) = match config::signing_algorithm()? {
            SigningAlgorithm::Rs256 => {
                let Some(pem) = config::pem("JWT_PUBLIC_KEY_PATH", "JWT_PUBLIC_KEY")? else {
                    return Ok(None);
                };
                (Algorithm::RS256, DecodingKey::from_rsa_pem(pem.as_bytes())?)
            }
            SigningAlgorithm::Hs256 => {
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
        };
        let issuer = crate::config::session_issuer();
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

    fn service_claims(&self, raw: &str) -> Option<Value> {
        let mut validation = self.validation.clone();
        validation.set_required_spec_claims(&["iss", "exp"]);
        Some(decode::<Value>(raw, &self.key, &validation).ok()?.claims)
    }

    fn read(&self, raw: &str) -> Option<Identity> {
        self.claims(raw)?.identity()
    }

    fn claims(&self, raw: &str) -> Option<Claims> {
        Some(
            decode::<Claims>(raw, &self.key, &self.validation)
                .ok()?
                .claims,
        )
    }

    pub(crate) fn consent_ticket(&self, raw: &str) -> Option<crate::consent_http::Ticket> {
        let ticket = decode::<crate::consent_http::Ticket>(raw, &self.key, &self.validation)
            .ok()?
            .claims;
        (ticket.kind == "consent").then_some(ticket)
    }

    pub(crate) async fn browser_session(
        &self,
        headers: &HeaderMap,
        tx: &mut Transaction<'_, Postgres>,
        enforce: bool,
    ) -> Result<Option<crate::browser_client::grant::BrowserSession>, sqlx::Error> {
        let Some(claims) = credential(headers).and_then(|raw| self.claims(raw)) else {
            return Ok(None);
        };
        let Some(identity) = claims.identity() else {
            return Ok(None);
        };
        if identity.client_bound || (enforce && revoked(tx, &identity).await?) {
            return Ok(None);
        }
        let authenticated_at = claims
            .auth_time
            .as_i64()
            .and_then(|t| DateTime::from_timestamp(t, 0));
        let methods: std::collections::BTreeSet<_> = claims
            .amr
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let amr = authenticated_at.and_then(|_| {
            (!methods.is_empty()).then(|| methods.into_iter().collect::<Vec<_>>().join(" "))
        });
        Ok(Some(crate::browser_client::grant::BrowserSession {
            user: identity.user,
            authenticated_at,
            amr,
        }))
    }
}

impl Claims {
    fn identity(&self) -> Option<Identity> {
        if self
            .client_id
            .as_ref()
            .is_some_and(|id| id.starts_with("dcr_"))
        {
            return None;
        }
        self.user_identity()
    }

    fn user_identity(&self) -> Option<Identity> {
        if self.kind != "access" {
            return None;
        }
        Some(Identity {
            user: self.sub.parse().ok()?,
            jti: self.jti.parse().ok()?,
            sid: match &self.sid {
                Some(s) => Some(s.parse().ok()?),
                None => None,
            },
            iat: self.iat,
            client_bound: self.client_id.is_some(),
        })
    }
}

#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    auth_time: Value,
    #[serde(default)]
    amr: Value,
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

async fn authenticated_transaction(
    state: &Profile,
    id: &Identity,
) -> Result<Option<Transaction<'static, Postgres>>, Box<Response>> {
    if state.enforce {
        let Ok(mut tx) = state.pool.begin().await else {
            return Err(Box::new(internal()));
        };
        match account_revoked(&mut tx, id).await {
            Ok(false) => Ok(Some(tx)),
            Ok(true) => Err(Box::new(unauthorized())),
            Err(_) => Err(Box::new(internal())),
        }
    } else {
        Ok(None)
    }
}

async fn account_revoked(tx: &mut Transaction<'_, Postgres>, id: &Identity) -> sqlx::Result<bool> {
    // Loading the account for the revocation check also decodes its stored metadata.
    let metadata: Option<String> =
        sqlx::query_scalar("SELECT extra_metadata::text FROM users WHERE id=$1")
            .bind(id.user)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some(metadata) = metadata {
        administrator::validate_metadata(&metadata)?;
    }
    revoked(tx, id).await
}

async fn recent(
    tx: &mut Transaction<'_, Postgres>,
    id: &Identity,
    require_mfa: bool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT FROM sessions s WHERE s.id=$1 AND s.user_id=$2
            AND s.revoked_at IS NULL AND s.expires_at > statement_timestamp()
            AND ((s.auth_time BETWEEN statement_timestamp()-interval '5 minutes' AND statement_timestamp()
                  AND (NOT $3 OR regexp_split_to_array(s.amr, '[[:space:]]+') @> ARRAY['mfa'])
                  AND regexp_split_to_array(s.amr, '[[:space:]]+') && ARRAY['pwd','fed','pop','swk'])
                 OR EXISTS (
                     SELECT FROM passkey_reauthentication r JOIN passkeys p ON p.id=r.credential_id
                     WHERE r.session_id=s.id AND r.user_id=s.user_id AND p.user_id=s.user_id
                     AND p.revoked_at IS NULL AND r.verified_at >= statement_timestamp()-interval '5 minutes'
                 )))",
    ).bind(id.sid).bind(id.user).bind(require_mfa).fetch_one(&mut **tx).await
}

fn timestamp(created: DateTime<Utc>) -> String {
    let precision = if created.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    created.to_rfc3339_opts(precision, true)
}

struct Profile {
    apple: Option<apple::Store>,
    google_play: Option<google_play::Provider>,
    stripe_checkout: Option<stripe_checkout::Provider>,
    stripe_events: Option<stripe_events::Verifier>,
    blockchain: Arc<crate::chain_settings::ChainSettings>,
    configured_origins: Vec<Value>,
    configured_resources: crate::token_runtime::ResourceRegistry,
    builtin_scopes: std::collections::BTreeMap<String, String>,
    client_scopes: tokio::sync::OnceCell<crate::discovery::ScopeRegistry>,
    admin_enabled: bool,
    passkeys: passkeys::Inventory,
    oidc_enabled: bool,
    provisioning: provisioning::Settings,
    registration: registration::Settings,
    wallet_export: wallet_export::Settings,
    wallet_challenges: wallet_challenge::issue::Settings,
    erasure: erasure::Settings,
    export_quota: crate::login_throttle::LoginThrottle,
    account_mail: crate::email_delivery::ConfirmationMailer,
    reset_quota: crate::login_throttle::LoginThrottle,
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
    build_routes(
        pool,
        production,
        registries::configured_scopes()?,
        Default::default(),
        Arc::new(crate::chain_settings::ChainSettings::configured()?),
    )
}

pub async fn routes_with_admin_registry(
    pool: PgPool,
    production: bool,
    interval: std::time::Duration,
) -> Result<Router, Box<dyn Error>> {
    routes_with_scope_registry(pool, production, interval, None).await
}

pub async fn routes_with_scope_registry(
    pool: PgPool,
    production: bool,
    interval: std::time::Duration,
    provider: Option<&mut crate::discovery::Provider>,
) -> Result<Router, Box<dyn Error>> {
    Ok(routes_with_policy(
        pool,
        production,
        interval,
        provider,
        None,
        Arc::new(crate::chain_settings::ChainSettings::configured()?),
    )
    .await?
    .0)
}

pub(crate) async fn routes_with_policy(
    pool: PgPool,
    production: bool,
    interval: std::time::Duration,
    provider: Option<&mut crate::discovery::Provider>,
    browser: Option<crate::browser_policy::BrowserPolicy>,
    blockchain: Arc<crate::chain_settings::ChainSettings>,
) -> Result<(Router, crate::token_runtime::ResourceCatalog), Box<dyn Error>> {
    let builtin_scopes = registries::configured_scopes()?;
    let resources = crate::token_http::configured_resources(provider.as_deref())?;
    let catalog = crate::discovery::ScopeRegistry::start(
        pool.clone(),
        builtin_scopes.clone(),
        provider,
        Some(resources),
        browser,
        interval,
    )
    .await;
    let resources = catalog
        .resources
        .clone()
        .expect("resource catalog configured");
    let router = build_routes(
        pool,
        production,
        builtin_scopes,
        tokio::sync::OnceCell::new_with(Some(catalog)),
        blockchain,
    )?;
    Ok((router, resources))
}

fn build_routes(
    pool: PgPool,
    production: bool,
    builtin_scopes: std::collections::BTreeMap<String, String>,
    client_scopes: tokio::sync::OnceCell<crate::discovery::ScopeRegistry>,
    blockchain: Arc<crate::chain_settings::ChainSettings>,
) -> Result<Router, Box<dyn Error>> {
    let state = Profile {
        apple: apple::Store::configured()?,
        google_play: google_play::Provider::configured()?,
        stripe_checkout: stripe_checkout::Provider::configured()?,
        stripe_events: stripe_events::Verifier::configured()?,
        blockchain,
        configured_origins: registries::origins::configured()?,
        configured_resources: crate::token_runtime::ResourceRegistry::from_env()?,
        builtin_scopes,
        client_scopes,
        admin_enabled: config::flag_with_default("ADMIN_API_ENABLED", true)?,
        passkeys: passkeys::Inventory::configured()?,
        oidc_enabled: config::flag("OIDC_ENABLED")?,
        provisioning: provisioning::Settings::configured()?,
        registration: registration::Settings::configured()?,
        wallet_export: wallet_export::Settings::configured()?,
        wallet_challenges: wallet_challenge::issue::Settings::configured()?,
        erasure: erasure::Settings::configured()?,
        export_quota: subject_export::quota(),
        account_mail: crate::email_delivery::ConfirmationMailer::configured()?,
        reset_quota: crate::login_throttle::LoginThrottle::with_window(
            env::var("RATELIMIT_RESET_PER_HOUR").map_or(Ok(5), |s| s.parse())?,
            std::time::Duration::from_secs(3600),
        ),
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
        .merge(analytics::routes())
        .merge(entitlement_reports::routes())
        .merge(audit_directory::routes())
        .merge(project_usage::routes())
        .merge(subject_export::routes())
        .merge(webhook_history::routes())
        .merge(hook_inventory::routes())
        .route("/api/v2/admin/hooks/validate", any(wasm_hooks::validate))
        .route("/api/v2/admin/hooks/artifacts", any(wasm_hooks::install))
        .route(
            "/api/v2/admin/hooks/artifacts/{digest}",
            any(wasm_hooks::download),
        )
        .route(
            "/api/v2/admin/hooks/artifacts/{digest}/test",
            any(wasm_hooks::dry_run),
        )
        .route(
            "/api/v2/admin/hooks/{hook_id}/binding",
            axum::routing::get(wasm_hooks::binding::read)
                .put(wasm_hooks::binding::write)
                .delete(wasm_hooks::binding::write)
                .layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .merge(store_products::routes())
        .route(
            "/api/v1/billing/apple/validate",
            any(apple::handle).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/billing/google/validate",
            any(google_play::handle).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/api/v1/webhooks/apple", any(apple::notifications::handle))
        .route(
            "/api/v1/webhooks/google",
            any(google_play::notifications::handle),
        )
        .route(
            "/api/v1/webhooks/stripe",
            any(stripe_events::handle).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/billing/stripe/checkout",
            any(stripe_checkout::handle).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/api/v1/orgs/{org_id}/members", any(org_directory::read))
        .route(
            "/api/v1/admin/settings/blockchain",
            any(blockchain::get).put(blockchain::update),
        )
        .route(
            "/api/v1/clients/me/rebac/check",
            axum::routing::post(rebac::check),
        )
        .route(
            "/api/v1/clients/me/rebac/relationships",
            axum::routing::put(rebac::write).delete(rebac::write),
        )
        .route(
            "/api/v1/clients/me/rebac/model",
            axum::routing::put(rebac::put_model),
        )
        .route(
            "/api/v1/clients/me/permissions",
            any(admin_permissions::delegated_list).post(admin_permissions::create),
        )
        .route(
            "/api/v1/clients/me/permissions/{key}",
            any(admin_permissions::remove),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/permissions",
            any(admin_permissions::list).post(admin_permissions::create),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/permissions/{key}",
            any(admin_permissions::remove),
        )
        .route(
            "/api/v1/clients/me/users/{user_id}/roles",
            any(admin_client_roles::delegated_user).post(admin_client_roles::grant::<true>),
        )
        .route(
            "/api/v1/clients/me/users/{user_id}/roles/{role_key}",
            any(admin_client_roles::revoke),
        )
        .route(
            "/api/v1/clients/me/roles",
            any(admin_client_roles::read).post(admin_client_roles::create),
        )
        .route(
            "/api/v1/clients/me/roles/{role_key}",
            any(admin_client_roles::remove),
        )
        .route(
            "/api/v1/clients/me/roles/{role_key}/permissions",
            any(admin_client_roles::read).put(admin_client_roles::put),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/roles",
            any(admin_client_roles::read).post(admin_client_roles::create),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/roles/{role_key}",
            any(admin_client_roles::remove),
        )
        .route(
            "/api/v1/admin/clients/{client_id}/roles/{role_key}/permissions",
            any(admin_client_roles::read).put(admin_client_roles::put),
        )
        .route("/api/v1/admin/blockchain/health", any(blockchain::health))
        .route(
            "/api/v1/admin/settings/auth-policy",
            any(auth_policy::get).put(auth_policy::update),
        )
        .route(
            "/api/v1/admin/users",
            any(admin_users::list).post(registration::admin::create),
        )
        .route(
            "/api/v1/admin/users/bulk",
            any(registration::bulk::handle).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/users/{user_id}",
            any(admin_users::detail).delete(erasure::remove),
        )
        .route(
            "/api/v1/admin/policies/{policy_id}",
            any(admin_inventory::policy)
                .put(admin_inventory::replace)
                .delete(admin_inventory::remove)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/policies",
            any(admin_inventory::policies)
                .post(admin_inventory::create)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/groups/{group_id}",
            any(admin_inventory::delete_group),
        )
        .route(
            "/api/v1/admin/roles/{role_id}",
            any(admin_inventory::delete_only).delete(admin_inventory::delete_role),
        )
        .route(
            "/api/v1/admin/roles/{role_id}/policies",
            any(crate::token_http::post_only)
                .post(admin_inventory::attach_role_policy)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/roles/{role_id}/policies/{policy_id}",
            any(admin_inventory::delete_only).delete(admin_inventory::detach_role_policy),
        )
        .route(
            "/api/v1/admin/groups/{group_id}/policies",
            any(crate::token_http::post_only)
                .post(admin_inventory::attach_group_policy)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/groups/{group_id}/policies/{policy_id}",
            any(admin_inventory::delete_only).delete(admin_inventory::detach_group_policy),
        )
        .route(
            "/api/v1/admin/users/{user_id}/groups",
            any(crate::token_http::post_only)
                .post(admin_inventory::add_member)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/users/{user_id}/groups/{group_id}",
            any(admin_inventory::delete_only).delete(admin_inventory::remove_member),
        )
        .route(
            "/api/v1/admin/users/{user_id}/nft/status",
            any(admin_inventory::token_status::patch_only)
                .patch(admin_inventory::token_status::update)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/users/{user_id}/nft/retry",
            any(crate::token_http::post_only).post(admin_inventory::token_retry::retry),
        )
        .route(
            "/api/v1/admin/users/{user_id}/nft",
            any(admin_inventory::user_token),
        )
        .route(
            "/api/v1/admin/users/{user_id}/iam",
            any(admin_inventory::user_iam),
        )
        .route(
            "/api/v1/admin/users/{user_id}/policies",
            any(crate::token_http::post_only)
                .post(admin_inventory::attach_user_policy)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/users/{user_id}/policies/{policy_id}",
            any(admin_inventory::delete_only).delete(admin_inventory::detach_user_policy),
        )
        .route(
            "/api/v1/admin/identities",
            any(crate::token_http::post_only)
                .post(admin_inventory::create_identity::create)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/identities/{identity_id}",
            any(admin_inventory::boundary::lookup),
        )
        .route(
            "/api/v1/admin/identities/{identity_id}/boundary",
            any(crate::token_http::post_only)
                .post(admin_inventory::boundary::set)
                .delete(admin_inventory::boundary::clear)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/iam/import",
            any(crate::token_http::post_only).post(admin_inventory::import::run),
        )
        .route(
            "/api/v1/admin/iam/export",
            any(admin_inventory::export::get),
        )
        .route(
            "/api/v1/admin/iam/evaluate",
            any(crate::token_http::post_only)
                .post(admin_inventory::evaluation::evaluate)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/roles/{role_id}/sessions",
            any(admin_inventory::role_sessions::list)
                .post(admin_inventory::assume_role::create)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/roles/sessions/{session_id}",
            any(admin_inventory::role_sessions::session_method)
                .delete(admin_inventory::role_sessions::revoke)
                .post(admin_inventory::assume_role::create)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/roles",
            any(admin_inventory::roles)
                .post(admin_inventory::create_role::create)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/groups",
            any(admin_inventory::groups)
                .post(admin_inventory::create_group)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/organizations",
            any(admin_organizations::list)
                .post(admin_organizations::create)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/organizations/{org_id}",
            any(admin_organizations::detail)
                .patch(admin_organizations::edit)
                .delete(admin_organizations::deactivate)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/users/{user_id}/organization",
            any(administrator::put_required)
                .put(admin_organizations::assign)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/users/{user_id}/organizations",
            any(admin_organizations::memberships)
                .post(admin_organizations::assign)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/users/{user_id}/organizations/{organization_id}",
            any(admin_organizations::remove),
        )
        .route(
            "/api/v1/admin/users/{user_id}/roles",
            any(admin_client_roles::list_user).post(admin_client_roles::grant::<false>),
        )
        .route(
            "/api/v1/admin/users/{user_id}/roles/{client_id}/{role_key}",
            any(admin_client_roles::revoke),
        )
        .route(
            "/api/v1/admin/users/{user_id}/passkeys",
            any(passkeys::admin_list),
        )
        .route(
            "/api/v1/admin/users/{user_id}/passkeys/{passkey_id}",
            any(passkeys::admin_revoke),
        )
        .route(
            "/api/v1/admin/users/{user_id}/wallet",
            any(crate::token_http::post_only).post(admin_wallet::ensure),
        )
        .route("/api/v1/admin/users/{user_id}/mfa", any(admin_mfa::reset))
        .route(
            "/api/v1/admin/users/{user_id}/password",
            any(administrator::put_required)
                .put(admin_password::reset)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/admin/users/{user_id}/admin",
            any(administrator::put_required)
                .put(admin_role::set)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/api/v1/admin/sessions", any(admin_sessions::list))
        .route(
            "/api/v1/admin/sessions/{session_id}",
            any(admin_sessions::revoke),
        )
        .route(
            "/api/v1/admin/oauth/web-origins",
            any(registries::list_origins).post(registries::create_origin),
        )
        .route(
            "/api/v1/admin/oauth/web-origins/{origin_id}",
            any(registries::get_origin)
                .delete(registries::deactivate_origin)
                .patch(registries::update_origin),
        )
        .route(
            "/api/v1/admin/oauth/protected-resources",
            any(registries::list_resources).post(registries::create_resource),
        )
        .route(
            "/api/v1/admin/oauth/protected-resources/{entry_id}",
            any(registries::get_resource)
                .delete(registries::deactivate_resource)
                .patch(registries::update_resource),
        )
        .route(
            "/api/v1/admin/oauth/scopes",
            any(registries::list_scopes).post(registries::create),
        )
        .route(
            "/api/v1/admin/oauth/scopes/{name}",
            any(registries::get_scope)
                .delete(registries::deactivate)
                .patch(registries::update),
        )
        .route(
            "/api/v1/admin/oauth/clients/{client_id}/rotate-secret",
            any(admin_clients::rotate),
        )
        .route(
            "/api/v1/admin/oauth/clients",
            any(admin_clients::list).post(admin_clients::create),
        )
        .route(
            "/api/v1/admin/oauth/clients/{client_id}",
            any(admin_clients::detail).patch(admin_clients::update),
        )
        .route("/api/v1/auth/oauth2/userinfo", any(userinfo::handle))
        .route(
            "/api/v1/auth/passkeys/login/options",
            any(passkeys::start_login),
        )
        .route(
            "/api/v1/auth/passkeys/reauth/verify",
            any(passkeys::reauthenticate),
        )
        .route(
            "/api/v1/auth/passkeys/reauth/options",
            any(passkeys::start_reauthentication),
        )
        .route(
            "/api/v1/auth/passkeys/register/options",
            any(passkeys::start_enrollment),
        )
        .route(
            "/api/v1/auth/passkeys/register/verify",
            any(passkeys::finish_enrollment),
        )
        .route("/api/v1/auth/passkeys", any(passkeys::list))
        .route("/api/v1/auth/passkeys/{passkey_id}", any(passkeys::modify))
        .route("/api/v1/auth/register", any(registration::handle))
        .route(
            "/api/v1/users/provision",
            any(crate::token_http::post_only)
                .post(provisioning::handle)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/api/v1/users/me", any(current))
        .route("/api/v1/auth/verify-email", any(email_verification::handle))
        .route("/api/v1/auth/mfa/status", any(enrollment::handle))
        .route("/api/v1/auth/mfa/totp/setup", any(totp::setup))
        .route("/api/v1/auth/mfa/totp/enable", any(totp::enable))
        .route("/api/v1/auth/mfa/totp/recovery-codes", any(totp::rotate))
        .route("/api/v1/auth/mfa/totp/disable", any(totp::disable))
        .route(
            "/api/v1/auth/password/reset-confirm",
            any(password_reset::confirm),
        )
        .route(
            "/api/v1/auth/password/reset-request",
            any(password_reset::request),
        )
        .route(
            "/api/v1/auth/wallet/challenge",
            any(crate::token_http::post_only)
                .post(wallet_challenge::issue::create)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/api/v1/auth/wallet/challenge/{challenge_id}",
            any(wallet_challenge::get),
        )
        .route("/api/v1/auth/password/change", any(password_change::handle))
        .route("/api/v1/auth/logout-all", any(logout_all::handle))
        .route(
            "/api/v1/users/{user_id}/roles",
            any(admin_client_roles::claims::<false>),
        )
        .route(
            "/api/v1/users/{user_id}/permissions",
            any(admin_client_roles::claims::<true>),
        )
        .route("/api/v1/users/me/private-key", any(wallet_export::handle))
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
    crate::headers::unhandled_error()
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
    doc["created_at"] = json!(timestamp(created));
    doc["is_admin"] = json!(config::effective_admin(
        doc["is_admin"] == true,
        doc["email"].as_str(),
        doc["is_email_verified"] == true,
        state.production,
        &state.admins
    ));
    let roles = if with_roles {
        token_authorization::profile_roles(&state.blockchain, tx, user).await?
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
