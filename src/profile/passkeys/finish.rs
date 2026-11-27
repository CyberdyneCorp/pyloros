use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    passkey_ceremonies::Enrollment,
    request_json::{parse_body, token_field},
};

pub(super) struct Proof {
    pub(super) ceremony: Uuid,
    credential: Value,
    name: String,
}

pub(in crate::profile) async fn handle(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    if req.method() != Method::POST {
        return post_required();
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 65536).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let input = match parse_body(&parts.headers, &bytes) {
        Ok(body) => parse(body),
        Err(issue) => return validation(vec![issue]),
    };
    let binding = state
        .passkeys
        .creation
        .as_ref()
        .and_then(|s| s.transport(&parts.headers, peer.ip(), false));
    run(
        &state,
        &parts.headers,
        peer.ip(),
        Operation::Finish(input, binding),
    )
    .await
}

fn parse(body: Value) -> Result<Proof, Vec<Value>> {
    if !body.is_object() {
        return Err(vec![token_field(body, "ceremony_id", 1, 64).unwrap_err()]);
    }
    let mut issues = Vec::new();
    let missing = |field: &str| json!({"loc":["body",field],"type":"missing","msg":"Field required","input":body});
    let ceremony = match body.get("ceremony_id") {
        Some(Value::String(s)) => rename::key_id(s).map_err(|mut issue| {
            issue["loc"] = json!(["body", "ceremony_id"]);
            issue
        }),
        Some(v) => Err(
            json!({"loc":["body","ceremony_id"],"type":"uuid_type","msg":"UUID input should be a string, bytes or UUID object","input":v}),
        ),
        None => Err(missing("ceremony_id")),
    };
    let ceremony = ceremony.map_err(|e| issues.push(e)).ok();
    let credential = body.get("credential");
    match credential {
        None=>issues.push(missing("credential")),
        Some(v) if !v.is_object()=>issues.push(json!({"loc":["body","credential"],"type":"dict_type","msg":"Input should be a valid dictionary","input":v})),
        _=>{}
    }
    let name = if body.get("name").is_some() {
        token_field(body.clone(), "name", 1, 64)
            .map_err(|e| issues.push(e))
            .ok()
    } else {
        None
    };
    if body.get("code").is_some_and(|v| !v.is_null())
        && let Err(e) = token_field(body.clone(), "code", 1, 16)
    {
        issues.push(e);
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    Ok(Proof {
        ceremony: ceremony.unwrap(),
        credential: credential.unwrap().clone(),
        name: name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Passkey")
            .into(),
    })
}

pub(super) fn invalid() -> Response {
    problem(
        StatusCode::UNAUTHORIZED,
        "Invalid passkey ceremony or authentication proof",
    )
}

pub(super) async fn register(
    state: &Profile,
    id: &Identity,
    enrollment: &Enrollment<'_>,
    proof: Proof,
    challenge: Vec<u8>,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let mut tx = state.pool.begin().await?;
    let account=sqlx::query_as::<_,(bool,Option<String>,Option<Uuid>)>(
        "SELECT u.totp_enabled,u.primary_email,u.organization_id FROM users u JOIN sessions s ON s.user_id=u.id
         WHERE u.id=$1 AND s.id=$2 AND u.is_active AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
         AND (u.tokens_valid_after IS NULL OR $3>floor(extract(epoch FROM u.tokens_valid_after))::bigint) FOR UPDATE OF u FOR SHARE OF s"
    ).bind(id.user).bind(enrollment.session).bind(id.iat).fetch_optional(&mut *tx).await?;
    let Some((mfa, email, organization)) = account else {
        return Ok(invalid());
    };
    if !recent(&mut tx, id, mfa).await? {
        return Ok(problem(
            StatusCode::FORBIDDEN,
            "Recent authentication required",
        ));
    }
    let rp = enrollment.relying_party.to_owned();
    let bound_origin = enrollment.origin.to_owned();
    let verified = tokio::task::spawn_blocking(move || {
        crate::passkey_attestation::verify(&rp, &bound_origin, &challenge, proof.credential)
    })
    .await;
    let key = match verified {
        Ok(Ok(key)) => key,
        Ok(Err(_)) => return Ok(invalid()),
        Err(_) => return Ok(internal()),
    };
    let record_id = Uuid::new_v4();
    let now = Utc::now();
    let row=sqlx::query("INSERT INTO passkeys(id,user_id,rp_id,credential_id,public_key,algorithm,sign_count,backup_eligible,backed_up,aaguid,transports,name,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING
        RETURNING id,name,created_at,last_used_at,backup_eligible,backed_up")
        .bind(record_id).bind(id.user).bind(enrollment.relying_party).bind(key.credential_id).bind(key.cose_key)
        .bind(key.algorithm).bind(i64::from(key.counter)).bind(key.backup_eligible).bind(key.backed_up)
        .bind(key.aaguid.to_string()).bind(key.transports).bind(proof.name).bind(now)
        .fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        return Ok(problem(
            StatusCode::CONFLICT,
            "This passkey is already registered",
        ));
    };
    let record = record(row)?;
    write_activity(
        &mut *tx,
        AuditActivity::PasskeyEnrolled(record_id),
        AuditSubject {
            user: Some(id.user),
            email,
            organization,
        },
        origin,
        request_id,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(record),
    )
        .into_response())
}
