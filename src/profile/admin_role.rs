//! Operator-managed administrator access.
use super::*;
use crate::{
    grant_audit::{AuditActivity, AuditSubject, write_activity},
    grant_response::SessionOrigin,
    login_http::problem,
    token_http::{client_ip, header as value},
};
use axum::extract::Path;

pub(super) fn status_field(body: Value) -> Result<bool, Value> {
    let body = admin_fields::object_field(&body)?;
    if !body.contains_key("is_admin") {
        return Err(
            json!({"type":"missing","loc":["body","is_admin"],"msg":"Field required","input":body}),
        );
    }
    let mut fields = admin_fields::Fields {
        body,
        issues: Vec::new(),
    };
    let flag = fields.boolean("is_admin");
    fields.issues.pop().map_or(Ok(flag), Err)
}

pub(super) async fn set(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    bytes: axum::body::Bytes,
) -> Response {
    let update =
        match administrator::user_update(&state, &headers, &raw, &bytes, "is_admin", status_field)
            .await
        {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let origin = SessionOrigin {
        ip: client_ip(&headers, peer.ip(), state.proxies),
        user_agent: value(&headers, "user-agent"),
    };
    apply(
        update,
        &state.admins,
        origin,
        value(&headers, "x-request-id"),
    )
    .await
    .unwrap_or_else(|_| internal())
}

async fn apply(
    update: administrator::UserUpdate<bool>,
    admins: &[String],
    origin: SessionOrigin<'_>,
    request: Option<&str>,
) -> Result<Response, sqlx::Error> {
    let administrator::UserUpdate {
        mut tx,
        actor,
        email: actor_email,
        user,
        input: grant,
    } = update;
    let activity = |previous| AuditActivity::AdminRole {
        operator: actor,
        grant,
        previous,
    };
    let mut subject = AuditSubject {
        user: Some(user),
        email: None,
        organization: None,
    };
    if user == actor {
        return Ok(refuse(
            tx,
            activity(Err("self_modification")),
            subject,
            origin,
            request,
            problem(
                StatusCode::BAD_REQUEST,
                "You cannot change your own admin status",
            ),
        )
        .await);
    }
    let row = sqlx::query_as::<_, (Option<String>, Option<Uuid>, bool)>(
        "SELECT primary_email,organization_id,is_admin FROM users WHERE id=$1",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, organization, previous)) = row else {
        return Ok(problem(StatusCode::NOT_FOUND, "User not found"));
    };
    subject.email = email;
    subject.organization = organization;
    if config::bootstrap_admin(subject.email.as_deref(), admins) {
        return Ok(refuse(
            tx,
            activity(Err("managed_by_config")),
            subject,
            origin,
            request,
            problem(
                StatusCode::CONFLICT,
                "This user's admin access is managed by server configuration",
            ),
        )
        .await);
    }
    if previous != grant {
        let updated = sqlx::query(
            "UPDATE users SET is_admin=$2, updated_at=now(),
            tokens_valid_after=CASE WHEN $2 THEN tokens_valid_after ELSE $3 END WHERE id=$1",
        )
        .bind(user)
        .bind(grant)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            return Ok(internal());
        }
    }
    write_activity(
        &mut *tx,
        activity(Ok(previous)),
        subject,
        origin,
        request,
        Utc::now(),
    )
    .await?;
    let action = if grant {
        "user.grant_admin"
    } else {
        "user.revoke_admin"
    };
    crate::admin_audit::append(
        &mut tx,
        action,
        Some((actor, actor_email.as_deref())),
        ("user", &user.to_string()),
        json!({}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok(
        Json(json!({"user_id":user,"is_admin":grant,"message":"Admin status updated"}))
            .into_response(),
    )
}

async fn refuse(
    mut tx: Transaction<'_, Postgres>,
    activity: AuditActivity<'_>,
    subject: AuditSubject,
    origin: SessionOrigin<'_>,
    request: Option<&str>,
    response: Response,
) -> Response {
    let recorded = async {
        write_activity(&mut *tx, activity, subject, origin, request, Utc::now()).await?;
        tx.commit().await
    }
    .await;
    if recorded.is_err() {
        eprintln!("Could not record administrator status refusal");
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_validation_distinguishes_large_numbers_from_unrecognized_boolean_values() {
        for (value, expected) in [
            (json!(2), "bool_parsing"),
            (json!(i64::MAX), "bool_parsing"),
            (json!(i64::MIN), "bool_parsing"),
            (json!(i64::MAX as u64 + 1), "bool_type"),
            (json!(-(2f64.powi(63))), "bool_type"),
            (json!(1.5), "bool_type"),
        ] {
            let issue = status_field(json!({"is_admin":value})).unwrap_err();
            assert_eq!(issue["type"], expected);
            assert_eq!(issue["input"], value);
        }
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn protected_accounts_keep_their_status_when_refusal_audit_is_unavailable() {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let actor = Uuid::new_v4();
        let managed = Uuid::new_v4();
        for (target, expected) in [
            (actor, StatusCode::BAD_REQUEST),
            (managed, StatusCode::CONFLICT),
        ] {
            let mut tx = pool.begin().await.unwrap();
            sqlx::raw_sql("CREATE TEMP TABLE users(id uuid,primary_email text,organization_id uuid,is_admin bool) ON COMMIT DROP;
                CREATE TEMP TABLE auth_events(id uuid CHECK(false)) ON COMMIT DROP;").execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO users VALUES ($1,'owner@example.test',NULL,false)")
                .bind(managed)
                .execute(&mut *tx)
                .await
                .unwrap();
            let update = administrator::UserUpdate {
                tx,
                actor,
                email: None,
                user: target,
                input: true,
            };
            let origin = SessionOrigin {
                ip: None,
                user_agent: None,
            };
            let response = apply(update, &["owner@example.test".into()], origin, None)
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
    }
}
