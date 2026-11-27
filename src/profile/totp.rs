//! Provision and confirm a first-party account's authenticator.
use super::*;
use crate::{
    enrolled_factor::FactorVerifier,
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    request_json::{parse_body, token_field},
    token_http::{client_ip, header as value},
};
use axum::body::to_bytes;
use base64::{Engine, engine::general_purpose::STANDARD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use qrcode::{EcLevel, QrCode, render::svg};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

const QUERY: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
const LABEL: &AsciiSet = &QUERY.remove(b'/');
type Tx<'a> = Transaction<'a, Postgres>;
type ResultResponse = Result<Response, Box<dyn Error + Send + Sync>>;
enum Action {
    Setup,
    Enable,
}

pub(super) async fn setup(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    handle(&state, peer, req, Action::Setup).await
}
pub(super) async fn enable(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    handle(&state, peer, req, Action::Enable).await
}

async fn handle(state: &Profile, peer: SocketAddr, req: Request, action: Action) -> Response {
    if req.method() != Method::POST {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return response;
    }
    let (parts, body) = req.into_parts();
    let input = if matches!(action, Action::Enable) {
        let Ok(bytes) = to_bytes(body, 2 * 1024 * 1024).await else {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        };
        match parse_body(&parts.headers, &bytes) {
            Ok(body) => Some(body),
            Err(issue) => return invalid_field(issue),
        }
    } else {
        None
    };
    let Some(id) = credential(&parts.headers).and_then(|t| state.verify.as_ref()?.read(t)) else {
        return unauthorized();
    };
    if id.client_bound {
        return unauthorized();
    }
    let origin = SessionOrigin {
        ip: client_ip(&parts.headers, peer.ip(), state.proxies),
        user_agent: value(&parts.headers, "user-agent"),
    };
    apply(
        state,
        id,
        input,
        origin,
        value(&parts.headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

fn invalid_field(issue: Value) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail":[issue]})),
    )
        .into_response()
}

async fn apply(
    state: &Profile,
    id: Identity,
    input: Option<Value>,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> ResultResponse {
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, &id).await? {
        return Ok(unauthorized());
    }
    let code = match input.map(|b| token_field(b, "code", 1, 16)).transpose() {
        Ok(code) => code,
        Err(issue) => return Ok(invalid_field(issue)),
    };
    let Some(factor) = &state.factor else {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Factor encryption key unavailable",
        ));
    };
    type Enrollment = (bool, Option<String>, Option<Uuid>, Option<Vec<u8>>);
    let record = sqlx::query_as::<_,Enrollment>(
        "SELECT totp_enabled,primary_email,organization_id,totp_secret_encrypted FROM users WHERE id=$1 FOR UPDATE"
    )
    .bind(id.user)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((enabled, email, organization, encrypted)) = record else {
        if code.is_some() {
            return refuse(&state.pool, tx, id.user, "user_not_found", origin, request).await;
        }
        return Ok(internal());
    };
    if let Some(code) = code {
        let now = Utc::now();
        let reason = if enabled {
            Some("mfa_already_enabled")
        } else if let Some(seed) = encrypted {
            let step = factor.timestep(&seed, &code, now)?;
            let changed = sqlx::query(
                "UPDATE users SET totp_enabled=true, totp_last_used_step=$2
                 WHERE id=$1 AND $2::bigint IS NOT NULL AND (totp_last_used_step IS NULL OR totp_last_used_step<$2)"
            )
            .bind(id.user)
            .bind(step)
            .execute(&mut *tx)
            .await?;
            (changed.rows_affected() == 0).then_some("mfa_failed")
        } else {
            Some("mfa_not_enrolled")
        };
        if let Some(reason) = reason {
            return refuse(&state.pool, tx, id.user, reason, origin, request).await;
        }
        let codes = replace_codes(&mut tx, id.user).await?;
        write_activity(
            &mut *tx,
            AuditActivity::Enroll(None),
            AuditSubject {
                user: Some(id.user),
                email,
                organization,
            },
            origin,
            request,
            now,
        )
        .await?;
        tx.commit().await?;
        return Ok(Json(json!({"recovery_codes":codes})).into_response());
    }
    if enabled {
        return Ok(problem(StatusCode::CONFLICT, "MFA already enabled"));
    }
    provision(tx, factor, id.user, email, &state.mfa_issuer).await
}

async fn provision(
    mut tx: Tx<'_>,
    factor: &FactorVerifier,
    user: Uuid,
    email: Option<String>,
    issuer: &str,
) -> ResultResponse {
    let (secret, encrypted) = factor.pending_seed()?;
    let account = email
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| user.to_string());
    let label = utf8_percent_encode(&account, LABEL);
    let uri = if issuer.is_empty() {
        format!("otpauth://totp/{label}?secret={secret}")
    } else {
        format!(
            "otpauth://totp/{}:{label}?secret={secret}&issuer={}",
            utf8_percent_encode(issuer, LABEL),
            utf8_percent_encode(issuer, QUERY)
        )
    };
    let svg = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M)?
        .render::<svg::Color>()
        .build();
    let qr = format!("data:image/svg+xml;base64,{}", STANDARD.encode(svg));
    sqlx::query("UPDATE users SET totp_secret_encrypted=$2 WHERE id=$1")
        .bind(user)
        .bind(encrypted)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"secret":secret,"provisioning_uri":uri,"qr_data_uri":qr})).into_response())
}

async fn replace_codes(
    tx: &mut Tx<'_>,
    user: Uuid,
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    let mut codes = Vec::with_capacity(10);
    let mut ids = Vec::with_capacity(10);
    let mut digests = Vec::with_capacity(10);
    while codes.len() < 10 {
        let mut bytes = [0u8; 5];
        OsRng.try_fill_bytes(&mut bytes)?;
        let hex = data_encoding::HEXLOWER.encode(&bytes);
        let code = format!("{}-{}", &hex[..5], &hex[5..]);
        if !codes.contains(&code) {
            ids.push(Uuid::new_v4());
            digests.push(format!("{:x}", Sha256::digest(code.as_bytes())));
            codes.push(code);
        }
    }
    sqlx::query(
        "INSERT INTO mfa_recovery_codes(id,user_id,code_hash)
                 SELECT id,$1,digest FROM unnest($2::uuid[], $3::text[]) AS codes(id,digest)",
    )
    .bind(user)
    .bind(ids)
    .bind(digests)
    .execute(&mut **tx)
    .await?;
    Ok(codes)
}

async fn refuse(
    pool: &PgPool,
    tx: Tx<'_>,
    user: Uuid,
    reason: &'static str,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> ResultResponse {
    tx.rollback().await?;
    if write_activity(
        pool,
        AuditActivity::Enroll(Some(reason)),
        AuditSubject {
            user: Some(user),
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
        eprintln!("could not record refused authenticator enrollment");
    }
    Ok(match reason {
        "mfa_already_enabled" => problem(StatusCode::CONFLICT, "MFA already enabled"),
        "mfa_not_enrolled" => problem(StatusCode::BAD_REQUEST, "Start MFA setup first"),
        "mfa_failed" => problem(StatusCode::BAD_REQUEST, "Invalid code"),
        _ => internal(),
    })
}
