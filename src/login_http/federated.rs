use super::*;
use crate::external_oauth::{account::Account, state::ReturnInstructions};
use crate::first_party::SessionPair;

impl Login {
    pub(crate) async fn federated(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account: &Account,
        delivery: &ReturnInstructions,
        default_target: Option<&str>,
        now: chrono::DateTime<Utc>,
    ) -> LoginResult {
        let policy = LoginPolicy {
            access_lifetime: self.access,
            admin_emails: &self.admins,
            require_verified_admin_email: self.production,
        };
        let login = AuthenticatedLogin {
            user: account.user,
            authenticated_at: now,
            methods: &["fed"],
            origin: SessionOrigin {
                ip: None,
                user_agent: None,
            },
        };
        let pair = self
            .issuer
            .issue_first_party(tx, login, &policy, now)
            .await?;
        let target = delivery
            .frontend_redirect
            .as_deref()
            .filter(|s| !s.is_empty());
        if delivery.return_mode == "fragment" {
            return Ok(self.fragment(
                target.ok_or("missing fragment destination")?,
                &pair,
                account.created,
            ));
        }
        cookie_return(
            &self.cookies,
            &pair,
            account.created,
            target.or(default_target),
            self.access.num_seconds() as u64,
            self.refresh.num_seconds() as u64,
        )
    }

    fn fragment(&self, target: &str, pair: &SessionPair, created: bool) -> Response {
        let mut fields = url::form_urlencoded::Serializer::new(String::new());
        fields
            .append_pair("access_token", &pair.access_token)
            .append_pair("refresh_token", &pair.refresh_token)
            .append_pair("token_type", "Bearer")
            .append_pair("expires_in", &self.access.num_seconds().to_string())
            .append_pair("is_new_user", if created { "true" } else { "false" });
        crate::browser_http::redirect(format!(
            "{target}#{}",
            crate::browser_prompt::encode_query(fields)
        ))
    }
}

fn cookie_return(
    cookies: &SessionCookies,
    pair: &SessionPair,
    created: bool,
    target: Option<&str>,
    access_seconds: u64,
    refresh_seconds: u64,
) -> LoginResult {
    let mut response = match target {
        Some(url) => crate::browser_http::redirect(url.into()),
        None => Json(json!({
            "access_token":pair.access_token, "refresh_token":pair.refresh_token,
            "token_type":"Bearer", "is_new_user":created
        }))
        .into_response(),
    };
    cookies.set(
        response.headers_mut(),
        &pair.access_token,
        &pair.refresh_token,
        access_seconds,
        refresh_seconds,
    )?;
    if target.is_none() {
        // The reference JSON response copies the first Set-Cookie value into a single-value header map.
        if let Some(access) = response.headers().get(h::SET_COOKIE).cloned() {
            response.headers_mut().insert(h::SET_COOKIE, access);
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn json_and_redirect_preserve_their_cookie_contracts() {
        let pair = SessionPair {
            session: Uuid::new_v4(),
            access_token: "access".into(),
            refresh_token: "refresh".into(),
        };
        let cookies = SessionCookies::configured(false).unwrap();
        let json = cookie_return(&cookies, &pair, true, None, 60, 600).unwrap();
        assert_eq!(json.status(), StatusCode::OK);
        let values: Vec<_> = json.headers().get_all(h::SET_COOKIE).iter().collect();
        assert_eq!(values.len(), 1);
        assert!(
            values[0]
                .to_str()
                .unwrap()
                .starts_with("access_token=access;")
        );
        let body = axum::body::to_bytes(json.into_body(), 2048).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            json!({"access_token":"access","refresh_token":"refresh","token_type":"Bearer","is_new_user":true})
        );
        let target = "https://app.example/complete";
        let redirect = cookie_return(&cookies, &pair, false, Some(target), 60, 600).unwrap();
        assert_eq!(redirect.status(), StatusCode::FOUND);
        assert_eq!(redirect.headers()[h::LOCATION], target);
        assert_eq!(redirect.headers().get_all(h::SET_COOKIE).iter().count(), 3);
    }
}
