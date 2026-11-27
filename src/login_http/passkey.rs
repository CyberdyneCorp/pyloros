use super::*;
use crate::{
    login_throttle::RateLimited,
    passkey_assertion::{self, AssertionError, StoredCredential},
    passkey_ceremonies::CeremonyBinding,
    profile::passkeys::{self, CeremonySettings, Proof},
};
use axum::http::Method;
use sha2::{Digest, Sha256};

pub(super) struct Policy {
    pub(super) rp: String,
    pub(super) settings: CeremonySettings,
    quota: LoginThrottle,
}

impl Policy {
    pub(super) fn configured() -> Result<Option<Self>, Box<dyn Error>> {
        let dev = env::var("APP_ENV").unwrap_or_else(|_| "dev".into()) == "dev";
        let Some(rp) = crate::login_methods::passkey_rp(dev)? else {
            return Ok(None);
        };
        let settings = CeremonySettings::configured(&rp)?;
        let limit = crate::token_runtime::number("PASSKEYS_RATE_LIMIT_PER_MIN", 10)?;
        Ok(Some(Self {
            rp,
            settings,
            quota: LoginThrottle::new(limit),
        }))
    }
}

pub(super) async fn handle(
    State(login): State<Option<Arc<Login>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return passkeys::post_required();
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 65536).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let document = match crate::request_json::parse_body(&parts.headers, &bytes) {
        Ok(v) => v,
        Err(e) => return passkeys::validation(vec![e]),
    };
    let Some(login) = login else {
        if !crate::config::flag("PASSKEYS_ENABLED").unwrap_or(false) {
            return problem(StatusCode::NOT_FOUND, "Passkeys disabled");
        }
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Login signing unavailable");
    };
    let Some(policy) = &login.passkeys else {
        return problem(StatusCode::NOT_FOUND, "Passkeys disabled");
    };
    let origin = SessionOrigin {
        ip: client_ip(&parts.headers, peer.ip(), login.proxies),
        user_agent: header(&parts.headers, "user-agent"),
    };
    if !policy.quota.allow(origin.ip) {
        return RateLimited.into_response();
    }
    let proof = match passkeys::parse_proof(document) {
        Ok(v) => v,
        Err(e) => return passkeys::validation(e),
    };
    let Some(transport) = policy.settings.transport(&parts.headers, peer.ip(), false) else {
        return passkeys::invalid_proof();
    };
    let binding = CeremonyBinding {
        relying_party: &policy.rp,
        origin: &transport.origin,
        binding: &transport.secret,
        policy_digest: &policy.settings.digest,
    };
    match login
        .passkey_signin(
            proof,
            &binding,
            origin,
            header(&parts.headers, "x-request-id"),
        )
        .await
    {
        Ok(mut response) => {
            if response.status().is_success() {
                response
                    .headers_mut()
                    .insert(h::CACHE_CONTROL, "no-store".parse().unwrap());
            }
            response
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"type":"about:blank","title":"Internal Server Error","status":500})),
        )
            .into_response(),
    }
}

struct Owner {
    user: Uuid,
    key: Uuid,
    mfa: bool,
    email: Option<String>,
    organization: Option<Uuid>,
}

impl Login {
    async fn passkey_signin(
        &self,
        proof: Proof,
        binding: &CeremonyBinding<'_>,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> LoginResult {
        let Some(challenge) = binding
            .claim_login(self.pool.begin().await?, proof.ceremony)
            .await?
        else {
            return self.refuse_assertion(false, origin, request).await;
        };
        let mut tx = self.pool.begin().await?;
        let owner = match authenticate(&mut tx, proof.credential, binding, challenge).await? {
            Ok(owner) => owner,
            Err(reason) => {
                tx.rollback().await?;
                return self
                    .refuse_assertion(reason == AssertionError::Counter, origin, request)
                    .await;
            }
        };
        if !owner.mfa {
            return self
                .finish(
                    tx,
                    owner.user,
                    origin,
                    request,
                    LoginMethod::Passkey(owner.key),
                )
                .await;
        }
        let pending = Uuid::new_v4();
        let nonce = rand::random::<[u8; 32]>();
        sqlx::query("INSERT INTO passkey_ceremonies(id,purpose,challenge,rp_id,origin,binding_hash,policy,expires_at,user_id,credential_id)
        VALUES($1,'mfa',$2,$3,$4,$5,$6,clock_timestamp()+interval '5 minutes',$7,$8)")
        .bind(pending)
        .bind(nonce.as_slice())
        .bind(binding.relying_party)
        .bind(binding.origin)
        .bind(format!("{:x}",Sha256::digest(binding.binding)))
        .bind(binding.policy_digest)
        .bind(owner.user)
        .bind(owner.key)
        .execute(&mut *tx)
        .await?;
        let now = Utc::now();
        let token = self.signing.issue_mfa(
            owner.user,
            crate::mfa_challenges::Binding::Passkey {
                passkey: owner.key,
                ceremony: pending,
            },
            now,
            self.challenge,
        )?;
        write_activity(
            &mut *tx,
            AuditActivity::PasskeyChallenge,
            AuditSubject {
                user: Some(owner.user),
                email: owner.email,
                organization: owner.organization,
            },
            origin,
            request,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(super::challenge("totp", token, None))
    }

    async fn refuse_assertion(
        &self,
        counter: bool,
        origin: SessionOrigin<'_>,
        request: Option<&str>,
    ) -> LoginResult {
        if write_activity(
            &self.pool,
            AuditActivity::PasskeyRefused(counter),
            AuditSubject {
                user: None,
                email: None,
                organization: None,
            },
            origin,
            request,
            Utc::now(),
        )
        .await
        .is_err()
        {
            eprintln!("could not record passkey refusal");
        }
        Ok(passkeys::invalid_proof())
    }
}

async fn authenticate(
    tx: &mut Transaction<'_, Postgres>,
    document: serde_json::Value,
    binding: &CeremonyBinding<'_>,
    challenge: Vec<u8>,
) -> Result<Result<Owner, AssertionError>, sqlx::Error> {
    let Some(credential) = document.get("id").and_then(|v| v.as_str()) else {
        return Ok(Err(AssertionError::Invalid));
    };
    // Lock the account before the credential, in the same order as enrollment and revocation.
    let account = sqlx::query_as::<_, (Uuid, bool, Option<String>, Option<Uuid>)>(
        "SELECT u.id,u.totp_enabled,u.primary_email,u.organization_id FROM users u JOIN passkeys p ON p.user_id=u.id
         WHERE p.rp_id=$1 AND p.credential_id=$2 AND u.is_active FOR UPDATE OF u")
        .bind(binding.relying_party)
        .bind(credential)
        .fetch_optional(&mut **tx)
        .await?;
    let Some((user, mfa, email, organization)) = account else {
        return Ok(Err(AssertionError::Invalid));
    };
    let entry = sqlx::query_as::<_, (Uuid, Vec<u8>, i64, bool, Vec<u8>)>(
        "SELECT p.id,p.public_key,p.sign_count,p.backup_eligible,h.handle FROM passkeys p JOIN passkey_handles h USING(user_id)
         WHERE p.user_id=$1 AND p.rp_id=$2 AND p.credential_id=$3 AND p.revoked_at IS NULL FOR UPDATE OF p")
        .bind(user)
        .bind(binding.relying_party)
        .bind(credential)
        .fetch_optional(&mut **tx)
        .await?;
    let Some((key, public_key, count, eligible, handle)) = entry else {
        return Ok(Err(AssertionError::Invalid));
    };
    let Ok(counter) = u32::try_from(count) else {
        return Ok(Err(AssertionError::Invalid));
    };
    let credential = credential.to_owned();
    let rp = binding.relying_party.to_owned();
    let origin = binding.origin.to_owned();
    let usage = tokio::task::spawn_blocking(move || {
        passkey_assertion::verify(
            &rp,
            &origin,
            &challenge,
            &StoredCredential {
                id: &credential,
                public_key: &public_key,
                user_handle: &handle,
                counter,
                backup_eligible: eligible,
            },
            document,
        )
    })
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let usage = match usage {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    sqlx::query(
        "UPDATE passkeys SET sign_count=$2,backed_up=$3,last_used_at=clock_timestamp() WHERE id=$1",
    )
    .bind(key)
    .bind(i64::from(usage.counter))
    .bind(usage.backed_up)
    .execute(&mut **tx)
    .await?;
    Ok(Ok(Owner {
        user,
        key,
        mfa,
        email,
        organization,
    }))
}

impl Login {
    pub(super) async fn claim_passkey_factor(
        &self,
        user: Uuid,
        key: Uuid,
        ceremony: Uuid,
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<Transaction<'_, Postgres>>, sqlx::Error> {
        let Some(policy) = &self.passkeys else {
            return Ok(None);
        };
        let Some(origin) = header(headers, "origin") else {
            return Ok(None);
        };
        let binding = if header(headers, "x-passkey-client") == Some("native") {
            header(headers, "x-passkey-binding").map(str::to_owned)
        } else {
            passkeys::binding_cookie(headers)
        };
        let Some(binding) = binding.filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        // Autocommit the one-use challenge before checking the factor code.
        let claimed = sqlx::query("UPDATE passkey_ceremonies SET consumed_at=clock_timestamp()
            WHERE id=$1 AND purpose='mfa' AND user_id=$2 AND credential_id=$3 AND origin=$4
            AND policy=$5 AND binding_hash=$6 AND consumed_at IS NULL AND expires_at>clock_timestamp()")
            .bind(ceremony)
            .bind(user)
            .bind(key)
            .bind(origin)
            .bind(&policy.settings.digest)
            .bind(format!("{:x}",Sha256::digest(binding)))
            .execute(&self.pool)
            .await?;
        if claimed.rows_affected() != 1 {
            return Ok(None);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user)
            .execute(&mut *tx)
            .await?;
        let live: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM passkeys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL)",
        )
        .bind(key)
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
        Ok(live.then_some(tx))
    }
}

#[cfg(test)]
mod tests;
