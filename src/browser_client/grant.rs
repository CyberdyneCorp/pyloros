//! Validate an authenticated browser grant and claim any existing user consent.
use super::BrowserClient;
use crate::{
    authorization_codes::{Grant, issue},
    browser_prompt::quoted_list,
};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// The resource URI maps to its configured API scopes.
pub type ResourceScopes = BTreeMap<String, BTreeSet<String>>;

pub struct AuthorizationRequest<'a> {
    pub response_type: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub challenge: Option<&'a str>,
    pub challenge_method: Option<&'a str>,
    pub resources: &'a [String],
    pub nonce: Option<String>,
    pub silent: bool,
}

pub struct BrowserSession {
    pub user: Uuid,
    pub authenticated_at: Option<DateTime<Utc>>,
    pub amr: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Issued(String),
    Approval {
        resource: String,
        scopes: String,
    },
    Denied {
        error: &'static str,
        description: String,
    },
}

fn denied(error: &'static str, description: impl Into<String>) -> Decision {
    Decision::Denied {
        error,
        description: description.into(),
    }
}

impl BrowserClient {
    fn pkce<'a>(&self, request: &AuthorizationRequest<'a>) -> Result<&'a str, Decision> {
        if !self
            .grant_types
            .split_whitespace()
            .any(|g| g == "authorization_code")
        {
            return Err(denied(
                "unauthorized_client",
                "client may not use the authorization_code grant",
            ));
        }
        if request.response_type != Some("code") {
            return Err(denied(
                "unsupported_response_type",
                "only response_type=code is supported",
            ));
        }
        match (request.challenge, request.challenge_method) {
            (Some(value), Some("S256")) if !value.is_empty() => Ok(value),
            _ => Err(denied(
                "invalid_request",
                "PKCE required: code_challenge + code_challenge_method=S256",
            )),
        }
    }

    fn resource<'a>(
        &self,
        requested: &'a [String],
        registry: &ResourceScopes,
    ) -> Result<Option<&'a str>, Decision> {
        match requested {
            [] if self.dynamic => Err(denied(
                "invalid_target",
                "resource is required for dynamically registered clients",
            )),
            [] => Ok(None),
            [uri] if registry.contains_key(uri) => Ok(Some(uri.as_str())),
            [_] => Err(denied("invalid_target", "unknown resource")),
            _ => Err(denied("invalid_target", "only one resource is supported")),
        }
    }

    fn approved_scopes<'a>(
        &self,
        raw: Option<&'a str>,
        resource: Option<&BTreeSet<String>>,
    ) -> Result<BTreeSet<&'a str>, Decision> {
        let requested: BTreeSet<_> = raw.unwrap_or_default().split_whitespace().collect();
        if requested.is_empty() {
            return Err(denied("invalid_scope", "scope is required"));
        }
        let allowed: BTreeSet<_> = self.scopes.split_whitespace().collect();
        let extra: Vec<_> = requested
            .iter()
            .copied()
            .filter(|s| {
                !allowed.contains(s)
                    || resource.is_some_and(|r| {
                        !matches!(*s, "openid" | "email" | "profile" | "offline_access")
                            && !r.contains(*s)
                    })
            })
            .collect();
        if extra.is_empty() {
            Ok(requested)
        } else {
            Err(denied(
                "invalid_scope",
                format!(
                    "scopes not allowed for this client: {}",
                    quoted_list(&extra)
                ),
            ))
        }
    }

    pub async fn authorize(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: BrowserSession,
        request: AuthorizationRequest<'_>,
        registry: &ResourceScopes,
        expires_at: DateTime<Utc>,
    ) -> Result<Decision, sqlx::Error> {
        let challenge = match self.pkce(&request) {
            Ok(value) => value,
            Err(error) => return Ok(error),
        };
        let resource = match self.resource(request.resources, registry) {
            Ok(value) => value,
            Err(error) => return Ok(error),
        };
        let scopes =
            match self.approved_scopes(request.scope, resource.and_then(|uri| registry.get(uri))) {
                Ok(scopes) => scopes,
                Err(error) => return Ok(error),
            };
        let scope = scopes.iter().copied().collect::<Vec<_>>().join(" ");
        if !self.trusted
            && !self
                .has_consent(tx, session.user, resource.unwrap_or_default(), &scopes)
                .await?
        {
            return Ok(if request.silent {
                denied("consent_required", "user approval required")
            } else {
                Decision::Approval {
                    resource: resource.unwrap_or_default().into(),
                    scopes: scope,
                }
            });
        }
        let grant = Grant {
            client_id: self.id.clone(),
            redirect_uri: self.callback.clone(),
            user_id: session.user,
            scopes: scope,
            challenge: challenge.into(),
            expires_at,
            nonce: request.nonce,
            resource: resource.map(str::to_owned),
            auth_time: session.authenticated_at,
            amr: session.amr,
        };
        Ok(Decision::Issued(issue(tx, &grant).await?))
    }

    async fn has_consent(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
        resource: &str,
        scopes: &BTreeSet<&str>,
    ) -> Result<bool, sqlx::Error> {
        let existing:Option<String>=sqlx::query_scalar("SELECT scopes FROM oauth_consents WHERE user_id=$1 AND client_id=$2 AND resource=$3 FOR SHARE")
            .bind(user).bind(&self.id).bind(resource).fetch_optional(&mut **tx).await?;
        Ok(existing.is_some_and(|stored| scopes.is_subset(&stored.split_whitespace().collect())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization_codes::find;
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn permission_is_bound_to_the_client_resource_user_and_scopes_before_code_issuance() {
        let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE oauth_consents(user_id uuid,client_id text,resource text,scopes text);
            CREATE TEMP TABLE oidc_authorization_codes(id uuid,code_hash text,client_id text,user_id uuid,redirect_uri text,scopes text,
            code_challenge text,code_challenge_method text,expires_at timestamptz,nonce text,resource text,auth_time timestamptz,amr text,consumed_at timestamptz,session_id uuid)")
            .execute(&mut *tx).await.unwrap();
        let client = BrowserClient {
            id: "native".into(),
            callback: "http://[::1]:3456/cb".into(),
            name: "Example".into(),
            trusted: false,
            dynamic: true,
            grant_types: "authorization_code".into(),
            scopes: "openid read write".into(),
        };
        let uri = "https://service.example";
        let resources = vec![uri.to_owned()];
        let registry = ResourceScopes::from([(uri.into(), BTreeSet::from(["read".into()]))]);
        let user = Uuid::new_v4();
        let now = DateTime::from_timestamp(1300000, 0).unwrap();
        let session = || BrowserSession {
            user,
            authenticated_at: Some(now),
            amr: Some("pwd".into()),
        };
        let request = |scope, silent| AuthorizationRequest {
            response_type: Some("code"),
            scope: Some(scope),
            challenge: Some("fixture-challenge"),
            challenge_method: Some("S256"),
            resources: &resources,
            nonce: Some("fixture-nonce".into()),
            silent,
        };
        assert!(matches!(
            client
                .authorize(&mut tx, session(), request("write", false), &registry, now)
                .await
                .unwrap(),
            Decision::Denied {
                error: "invalid_scope",
                ..
            }
        ));
        sqlx::query("INSERT INTO oauth_consents VALUES($1,'native',$2,'openid'),($3,'native',$2,'read openid'),($1,'native','elsewhere','read openid'),($1,'other',$2,'read openid')")
            .bind(user).bind(uri).bind(Uuid::new_v4()).execute(&mut *tx).await.unwrap();
        assert!(matches!(
            client
                .authorize(
                    &mut tx,
                    session(),
                    request("read openid", true),
                    &registry,
                    now
                )
                .await
                .unwrap(),
            Decision::Denied {
                error: "consent_required",
                ..
            }
        ));
        assert_eq!(
            client
                .authorize(
                    &mut tx,
                    session(),
                    request("read openid", false),
                    &registry,
                    now
                )
                .await
                .unwrap(),
            Decision::Approval {
                resource: uri.into(),
                scopes: "openid read".into()
            }
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_authorization_codes")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        sqlx::query("UPDATE oauth_consents SET scopes='read openid' WHERE client_id='native' AND user_id=$1 AND resource=$2")
            .bind(user).bind(uri).execute(&mut *tx).await.unwrap();
        let Decision::Issued(code) = client
            .authorize(
                &mut tx,
                session(),
                request("read read openid", false),
                &registry,
                now,
            )
            .await
            .unwrap()
        else {
            panic!("expected code")
        };
        let grant = find(&mut tx, &code, "native").await.unwrap().unwrap().grant;
        assert_eq!(grant.user_id, user);
        assert_eq!(grant.resource.as_deref(), Some(uri));
        assert_eq!(grant.scopes, "openid read");
        assert_eq!(grant.redirect_uri, client.callback);
        assert_eq!(grant.auth_time, Some(now));
        assert_eq!(grant.amr.as_deref(), Some("pwd"));
        assert_eq!(grant.nonce.as_deref(), Some("fixture-nonce"));
    }
}
