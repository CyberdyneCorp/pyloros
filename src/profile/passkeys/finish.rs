use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    passkey_ceremonies::Enrollment,
    request_json::token_field,
};

pub(crate) struct Proof {
    pub(crate) ceremony: Uuid,
    pub(crate) credential: Value,
    name: String,
    pub(super) code: Option<String>,
}

pub(in crate::profile) async fn handle(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    complete(state, peer, req, SessionProof::Register).await
}

pub(in crate::profile) async fn reauthenticate(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    complete(state, peer, req, SessionProof::Reauthenticate).await
}

async fn complete(
    state: Arc<Profile>,
    peer: SocketAddr,
    req: Request,
    purpose: SessionProof,
) -> Response {
    if req.method() != Method::POST {
        return post_required();
    }
    let (parts, body) = req.into_parts();
    let input = match proof_document(&parts.headers, body).await {
        Ok(document) => parse(document),
        Err(response) => return *response,
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
        Operation::Finish(purpose, input, binding),
    )
    .await
}

pub(crate) fn parse(body: Value) -> Result<Proof, Vec<Value>> {
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
    let code = if body.get("code").is_some_and(|v| !v.is_null()) {
        token_field(body.clone(), "code", 1, 16)
            .map_err(|e| issues.push(e))
            .ok()
    } else {
        None
    };
    if !issues.is_empty() {
        return Err(issues);
    }
    Ok(Proof {
        code,
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

pub(crate) fn invalid() -> Response {
    problem(
        StatusCode::UNAUTHORIZED,
        "Invalid passkey ceremony or authentication proof",
    )
}

pub(super) async fn register(
    pool: &PgPool,
    id: &Identity,
    enrollment: &Enrollment<'_>,
    proof: Proof,
    challenge: Vec<u8>,
    origin: SessionOrigin<'_>,
    request_id: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let mut tx = pool.begin().await?;
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
    commit_response(
        tx,
        (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, "no-store")],
            Json(record),
        ),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn rejected_enrollment_commit_discards_the_credential_and_activity() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("
            CREATE TEMP TABLE users(id uuid, totp_enabled bool, primary_email text, organization_id uuid, is_active bool, tokens_valid_after timestamptz);
            CREATE TEMP TABLE sessions(id uuid, user_id uuid, revoked_at timestamptz, expires_at timestamptz, auth_time timestamptz, amr text);
            CREATE TEMP TABLE passkey_reauthentication(session_id uuid, user_id uuid, credential_id uuid, verified_at timestamptz);
            CREATE TEMP TABLE passkeys(id uuid PRIMARY KEY, user_id uuid, rp_id text, credential_id text, public_key bytea, algorithm int,
                sign_count bigint, backup_eligible bool, backed_up bool, aaguid text, transports jsonb, name text, created_at timestamptz, last_used_at timestamptz, revoked_at timestamptz);
            CREATE TEMP TABLE auth_events(activity text UNIQUE DEFERRABLE INITIALLY DEFERRED);
            INSERT INTO auth_events VALUES ('passkey_enroll');
        ").execute(&pool).await.unwrap();
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        sqlx::query("INSERT INTO users VALUES ($1,false,NULL,NULL,true,NULL)")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions VALUES ($1,$2,NULL,now()+interval '1 hour',now(),'pwd')")
            .bind(session)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();

        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/passkey-attestations.json"
        ))
        .unwrap();
        let fixture = &fixtures[0];
        let enrollment = Enrollment {
            user,
            session,
            relying_party: "example.test",
            origin: fixture["origin"].as_str().unwrap(),
            binding: "test",
            policy_digest: "test",
        };
        let identity = Identity {
            user,
            sid: Some(session),
            client_bound: false,
            iat: None,
            jti: Uuid::new_v4(),
        };
        let proof = Proof {
            ceremony: Uuid::new_v4(),
            credential: fixture["proof"].clone(),
            name: "Example".into(),
            code: None,
        };
        let challenge = URL_SAFE_NO_PAD
            .decode(fixture["challenge"].as_str().unwrap())
            .unwrap();
        let origin = SessionOrigin {
            ip: None,
            user_agent: None,
        };
        let response = register(
            &pool,
            &identity,
            &enrollment,
            proof,
            challenge,
            origin,
            None,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM passkeys), (SELECT count(*) FROM auth_events)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(counts, (0, 1));
    }
}
