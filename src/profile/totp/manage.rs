//! Reverify the caller before replacing or removing enrolled credentials.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Rotate,
    Disable,
}

impl Operation {
    fn activity(self) -> &'static str {
        match self {
            Self::Rotate => "recovery_codes_regenerate",
            Self::Disable => "mfa_disable",
        }
    }
}

struct Proof {
    password: String,
    code: String,
}

fn parse(body: Value) -> Result<Proof, Vec<Value>> {
    let mut issues = Vec::new();
    let password = body.get("password").filter(|p| !p.is_null());
    if let Some(value) = password
        && !value.is_string()
    {
        issues.push(json!({"loc":["body","password"],"type":"string_type","msg":"Input should be a valid string","input":value}));
    }
    let password = password
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    match token_field(body, "code", 1, 32) {
        Ok(code) if issues.is_empty() => return Ok(Proof { password, code }),
        Err(issue) => issues.push(issue),
        _ => (),
    }
    Err(issues)
}

async fn verify_password(
    mut tx: Tx<'_>,
    scheme: crate::passwords::PasswordScheme,
    user: Uuid,
    password: String,
) -> Result<(Option<String>, bool), Box<dyn Error + Send + Sync>> {
    // Release the pool connection while waiting for a password worker. Recheck
    // the credential under the account lock before using the result.
    let hash: Option<String> = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1 AND totp_enabled AND totp_secret_encrypted IS NOT NULL")
        .bind(user).fetch_optional(&mut *tx).await?.flatten();
    tx.commit().await?;
    let verified = if hash.is_some() {
        scheme.verify(password, hash.clone()).await?
    } else {
        false
    };
    Ok((hash, verified))
}

pub(super) async fn apply(
    state: &Profile,
    tx: Tx<'_>,
    id: Identity,
    body: &RawValue,
    operation: Operation,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> ResultResponse {
    let proof = match fields::validate_scalar_document(body, &["password", "code"], parse) {
        Ok(proof) => proof,
        Err(response) => return Ok(*response),
    };
    let (hash, verified) = verify_password(tx, state.scheme, id.user, proof.password).await?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query_as::<_,(bool,Option<Vec<u8>>,Option<String>,Option<String>,Option<Uuid>)>(
        "SELECT totp_enabled,totp_secret_encrypted,password_hash,primary_email,organization_id FROM users WHERE id=$1 FOR UPDATE"
    ).bind(id.user).fetch_optional(&mut *tx).await?;
    if state.enforce && revoked(&mut tx, &id).await? {
        return Ok(unauthorized());
    }
    let (reason, email, organization) = match row {
        Some((true, Some(seed), stored, email, org)) => {
            let reason = if stored.is_some() && !(verified && stored == hash) {
                Some("bad_password")
            } else if stored.is_none() && !recent(&mut tx, &id, true).await? {
                Some("password_not_set")
            } else {
                let Some(factor) = state.factor.as_ref() else {
                    return Ok(problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Factor encryption key unavailable",
                    ));
                };
                let step = factor.timestep(&seed, &proof.code, Utc::now())?;
                let claimed = sqlx::query("UPDATE users SET totp_last_used_step=$2 WHERE id=$1 AND $2::bigint IS NOT NULL AND (totp_last_used_step IS NULL OR totp_last_used_step<$2)")
                    .bind(id.user).bind(step).execute(&mut *tx).await?;
                (claimed.rows_affected() == 0).then_some("mfa_failed")
            };
            (reason, email, org)
        }
        Some(_) => (Some("mfa_not_enrolled"), None, None),
        None => (Some("user_not_found"), None, None),
    };
    let response = match reason {
        Some(reason) => refusal(reason),
        None => change(&mut tx, id.user, operation).await?,
    };
    write_activity(
        &mut *tx,
        AuditActivity::Authenticator(operation.activity(), reason),
        AuditSubject {
            user: Some(id.user),
            email: email.filter(|_| reason.is_none()),
            organization: organization.filter(|_| reason.is_none()),
        },
        origin,
        request,
        Utc::now(),
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

fn refusal(reason: &str) -> Response {
    match reason {
        "bad_password" => problem(StatusCode::UNAUTHORIZED, "Invalid password"),
        "password_not_set" => problem(StatusCode::FORBIDDEN, "Recent authentication required"),
        "mfa_failed" => problem(StatusCode::BAD_REQUEST, "Invalid code"),
        "mfa_not_enrolled" => problem(StatusCode::BAD_REQUEST, "MFA is not enabled"),
        _ => internal(),
    }
}

async fn change(tx: &mut Tx<'_>, user: Uuid, operation: Operation) -> ResultResponse {
    match operation {
        Operation::Rotate => {
            Ok(Json(json!({"recovery_codes":replace_codes(tx,user).await?})).into_response())
        }
        Operation::Disable => {
            sqlx::query(
                "UPDATE users SET totp_enabled=false,totp_secret_encrypted=NULL WHERE id=$1",
            )
            .bind(user)
            .execute(&mut **tx)
            .await?;
            sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id=$1")
                .bind(user)
                .execute(&mut **tx)
                .await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_password_and_code_report_both_fields_in_order() {
        let Err(issues) = parse(json!({"password":42,"code":""})) else {
            panic!("invalid proof accepted")
        };
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0]["loc"], json!(["body", "password"]));
        assert_eq!(issues[1]["loc"], json!(["body", "code"]));
        assert!(parse(json!({"password":null,"code":"123456"})).is_ok());
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn passwordless_proof_is_bound_to_a_live_session_and_active_passkey() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE sessions(id uuid,user_id uuid,expires_at timestamptz,revoked_at timestamptz,auth_time timestamptz,amr text);
            CREATE TEMP TABLE passkeys(id uuid,user_id uuid,revoked_at timestamptz);
            CREATE TEMP TABLE passkey_reauthentication(session_id uuid,user_id uuid,credential_id uuid,verified_at timestamptz)")
            .execute(&mut *tx).await.unwrap();
        let id = Identity {
            user: Uuid::new_v4(),
            sid: Some(Uuid::new_v4()),
            jti: Uuid::new_v4(),
            iat: None,
            client_bound: false,
        };
        sqlx::query(
            "INSERT INTO sessions VALUES ($1,$2,now()+interval '1 day',null,now(),'fed mfa')",
        )
        .bind(id.sid)
        .bind(id.user)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(recent(&mut tx, &id, true).await.unwrap());
        sqlx::query("UPDATE sessions SET amr='fed'")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(!recent(&mut tx, &id, true).await.unwrap());
        sqlx::query("INSERT INTO passkeys VALUES ($1,$2,null)")
            .bind(id.jti)
            .bind(id.user)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO passkey_reauthentication VALUES ($1,$2,$3,now())")
            .bind(id.sid)
            .bind(id.user)
            .bind(id.jti)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(recent(&mut tx, &id, true).await.unwrap());
        for (field, reset) in [
            ("expires_at=now()", "expires_at=now()+interval '1 day'"),
            ("revoked_at=now()", "revoked_at=null"),
        ] {
            sqlx::query(&format!("UPDATE sessions SET {field}"))
                .execute(&mut *tx)
                .await
                .unwrap();
            assert!(!recent(&mut tx, &id, true).await.unwrap());
            sqlx::query(&format!("UPDATE sessions SET {reset}"))
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        sqlx::query("UPDATE passkeys SET revoked_at=now()")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(!recent(&mut tx, &id, true).await.unwrap());
    }
}
