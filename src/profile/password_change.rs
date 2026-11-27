//! Replace a first-party password and end sessions issued under the old credential.
use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    request_json::{parse_body, token_field},
    token_http::{client_ip, header as value},
};
use axum::body::to_bytes;
use unicode_general_category::{GeneralCategory::*, get_general_category};

fn valid_password(password: &str) -> bool {
    let line = password.strip_suffix('\n').unwrap_or(password);
    !line.contains('\n')
        && line.bytes().any(|b| b.is_ascii_lowercase())
        && line.bytes().any(|b| b.is_ascii_uppercase())
        && line
            .chars()
            .any(|c| get_general_category(c) == DecimalNumber)
        && line.chars().any(is_password_symbol)
}

fn is_password_symbol(c: char) -> bool {
    let word = matches!(
        get_general_category(c),
        UppercaseLetter
            | LowercaseLetter
            | TitlecaseLetter
            | ModifierLetter
            | OtherLetter
            | DecimalNumber
            | LetterNumber
            | OtherNumber
    );
    !(word || c == '_' || c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

pub(super) fn fields(body: Value, proof_field: &str) -> Result<(String, String), Vec<Value>> {
    if !body.is_object() {
        return Err(vec![
            token_field(body, proof_field, 0, usize::MAX).unwrap_err(),
        ]);
    }
    let current = token_field(body.clone(), proof_field, 0, usize::MAX);
    let new = password_field(body, "new_password");
    match (current, new) {
        (Ok(old), Ok(new)) => Ok((old, new)),
        (current, new) => Err(current.err().into_iter().chain(new.err()).collect()),
    }
}

pub(super) fn password_field(body: Value, field: &str) -> Result<String, Value> {
    token_field(body, field, 8, 128).and_then(|password| {
        if valid_password(&password) {
            return Ok(password);
        }
        let reason = "password must contain lower, upper, digit, and non-alphanumeric characters";
        Err(json!({"loc":["body",field],"type":"value_error","msg":format!("Value error, {reason}"),"input":password,"ctx":{"error":reason}}))
    })
}

pub(super) fn invalid(issues: Vec<Value>) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail":issues})),
    )
        .into_response()
}

pub(super) async fn read_body(req: Request) -> Result<(HeaderMap, Value), Box<Response>> {
    if req.method() != Method::POST {
        let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return Err(Box::new(response));
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = to_bytes(body, 2 * 1024 * 1024).await else {
        return Err(Box::new(StatusCode::PAYLOAD_TOO_LARGE.into_response()));
    };
    let body = match parse_body(&parts.headers, &bytes) {
        Ok(body) => body,
        Err(issue) => return Err(Box::new(invalid(vec![issue]))),
    };
    Ok((parts.headers, body))
}

pub(super) async fn handle(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (headers, body) = match read_body(req).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let Some(id) = credential(&headers).and_then(|t| state.verify.as_ref()?.read(t)) else {
        return unauthorized();
    };
    if id.client_bound {
        return unauthorized();
    }
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    change(&state, id, body, origin, value(&headers, "x-request-id"))
        .await
        .unwrap_or_else(|_| internal())
}

type ChangeResult = Result<Response, Box<dyn Error + Send + Sync>>;
async fn change(
    state: &Profile,
    id: Identity,
    body: Value,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> ChangeResult {
    let mut tx = state.pool.begin().await?;
    if state.enforce && revoked(&mut tx, &id).await? {
        return Ok(unauthorized());
    }
    let (current, new) = match fields(body, "current_password") {
        Ok(inputs) => inputs,
        Err(issues) => return Ok(invalid(issues)),
    };
    let observed: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id=$1")
            .bind(id.user)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    tx.commit().await?;
    let replacement = if state.scheme.verify(current, observed.clone()).await? {
        Some(state.scheme.hash(new).await?)
    } else {
        None
    };

    let mut tx = state.pool.begin().await?;
    let account = sqlx::query_as::<_, (Option<String>, Option<String>, Option<Uuid>)>(
        "SELECT password_hash,primary_email,organization_id FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(id.user)
    .fetch_optional(&mut *tx)
    .await?;
    if state.enforce && revoked(&mut tx, &id).await? {
        return Ok(unauthorized());
    }
    let now = Utc::now();
    let mut subject = AuditSubject {
        user: Some(id.user),
        email: None,
        organization: None,
    };
    let outcome = match (account, replacement) {
        (None, _) => Err("user_not_found"),
        (Some((None, _, _)), _) => Err("password_not_set"),
        (Some((stored, email, organization)), Some(hash)) if stored == observed => {
            sqlx::query("UPDATE users SET password_hash=$2,tokens_valid_after=GREATEST(tokens_valid_after,$3) WHERE id=$1")
                .bind(id.user).bind(hash).bind(now).execute(&mut *tx).await?;
            subject.email = email;
            subject.organization = organization;
            Ok(logout_all::revoke_sessions(&mut tx, id.user, now).await?)
        }
        _ => Err("bad_password"),
    };
    write_activity(
        &mut *tx,
        AuditActivity::PasswordChanged(outcome),
        subject,
        origin,
        request,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(if outcome.is_ok() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        problem(StatusCode::UNAUTHORIZED, "Current password is incorrect")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_character_classes() {
        assert!(valid_password("Abcdef١!"));
        assert!(!valid_password("Abcdef²!"));
        assert!(!valid_password("Abcdef1_"));
        assert!(valid_password("Abcdef1\u{345}"));
        assert!(!valid_password("Abc1!\nDef"));
        assert!(valid_password("Abcdef1!\n"));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn audit_failure_rolls_back_password_and_session_changes() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE users(id uuid,password_hash text,organization_id uuid,primary_email text,tokens_valid_after timestamptz);
            CREATE TEMP TABLE sessions(user_id uuid,revoked_at timestamptz);
            CREATE TEMP TABLE auth_events(activity text CHECK(activity <> 'password_change'))")
            .execute(&pool).await.unwrap();
        let user = Uuid::new_v4();
        let hash = bcrypt::hash("old", 4).unwrap();
        sqlx::query("INSERT INTO users(id,password_hash) VALUES($1,$2)")
            .bind(user)
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions VALUES($1,NULL)")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        let state = Profile {
            oidc_enabled: false,
            registration: registration::Settings::configured().unwrap(),
            account_mail: crate::email_delivery::ConfirmationMailer::mock(),
            reset_quota: crate::login_throttle::LoginThrottle::new(0),
            scheme: crate::passwords::PasswordScheme::Bcrypt,
            pool: pool.clone(),
            enforce: false,
            verify: None,
            admins: vec![],
            proxies: 0,
            production: false,
            factor: None,
            mfa_issuer: String::new(),
            cookies: crate::session_cookies::SessionCookies::configured(false).unwrap(),
        };
        let id = Identity {
            user,
            jti: Uuid::new_v4(),
            sid: None,
            iat: None,
            client_bound: false,
        };
        let origin = SessionOrigin {
            ip: None,
            user_agent: None,
        };
        assert!(
            change(
                &state,
                id,
                json!({"current_password":"old","new_password":"Fresh-Password1"}),
                origin,
                None
            )
            .await
            .is_err()
        );
        let state: (String,bool,bool) = sqlx::query_as("SELECT password_hash,tokens_valid_after IS NULL,revoked_at IS NULL FROM users JOIN sessions ON sessions.user_id=users.id")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(state, (hash, true, true));
    }
}
