//! Delivery of browser sign-in confirmation messages.
use crate::email_challenge::ConfirmationEmail;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use std::{env, sync::Mutex, time::Duration};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("invalid email provider configuration: {0}")]
    Configuration(&'static str),
    #[error("invalid sign-in email recipient or message")]
    Message,
    #[error("SMTP submission failed")]
    Transport(#[source] lettre::transport::smtp::Error),
}

pub struct ConfirmationMailer {
    provider: Provider,
}

enum Provider {
    Mock(Mutex<Vec<ConfirmationEmail>>),
    Smtp {
        relay: Box<AsyncSmtpTransport<Tokio1Executor>>,
        from: Mailbox,
        base: Option<Url>,
    },
}

fn setting(name: &str) -> Option<String> {
    env::var(name).ok().filter(|s| !s.is_empty())
}

fn account_base(explicit: Option<String>, login: Option<String>) -> Result<Option<Url>, MailError> {
    let use_origin = explicit.is_none();
    let Some(raw) = explicit.or(login) else {
        return Ok(None);
    };
    let mut url = Url::parse(&raw).map_err(|_| MailError::Configuration("invalid account URL"))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(MailError::Configuration("invalid account URL"));
    }
    if use_origin {
        url.set_path("/");
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(Some(url))
}

impl ConfirmationMailer {
    pub fn configured() -> Result<Self, MailError> {
        let provider = match setting("EMAIL_PROVIDER").as_deref().unwrap_or("mock") {
            "mock" => Provider::Mock(Mutex::new(Vec::new())),
            "smtp" => smtp_provider()?,
            _ => return Err(MailError::Configuration("unsupported EMAIL_PROVIDER")),
        };
        Ok(Self { provider })
    }

    pub async fn send(&self, email: ConfirmationEmail) -> Result<(), MailError> {
        match &self.provider {
            Provider::Mock(outbox) => {
                outbox.lock().expect("mock mail outbox").push(email);
                Ok(())
            }
            Provider::Smtp { relay, from, base } => {
                let base = base
                    .as_ref()
                    .ok_or(MailError::Configuration("missing account link base"))?;
                let message = confirmation_message(from, base, &email)?;
                relay.send(message).await.map_err(MailError::Transport)?;
                Ok(())
            }
        }
    }

    /// Take captured messages from the development provider.
    pub fn take_mock_messages(&self) -> Option<Vec<ConfirmationEmail>> {
        match &self.provider {
            Provider::Mock(outbox) => Some(std::mem::take(
                &mut *outbox.lock().expect("mock mail outbox"),
            )),
            Provider::Smtp { .. } => None,
        }
    }
}

fn smtp_provider() -> Result<Provider, MailError> {
    let host = setting("SMTP_HOST").ok_or(MailError::Configuration("missing SMTP_HOST"))?;
    let port = env::var("SMTP_PORT")
        .map_or(Ok(587), |s| s.parse())
        .map_err(|_| MailError::Configuration("invalid SMTP_PORT"))?;
    let builder = if port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
    };
    let mut builder = builder
        .map_err(MailError::Transport)?
        .port(port)
        .timeout(Some(Duration::from_secs(15)));
    if let Some(user) = setting("SMTP_USERNAME") {
        builder = builder.credentials(Credentials::new(
            user,
            setting("SMTP_PASSWORD").unwrap_or_default(),
        ));
    }
    let from = setting("EMAIL_FROM")
        .unwrap_or_else(|| "no-reply@cyberdyne.local".into())
        .parse()
        .map_err(|_| MailError::Configuration("invalid EMAIL_FROM"))?;
    let base = account_base(
        setting("ACCOUNT_LINKS_BASE_URL"),
        setting("OIDC_LOGIN_URL").or_else(|| setting("OAUTH_POST_LOGIN_URL")),
    )?;
    Ok(Provider::Smtp {
        relay: Box::new(builder.build()),
        from,
        base,
    })
}

fn confirmation_url(base: &Url, token: &str) -> Result<Url, MailError> {
    let mut link = base.clone();
    link.path_segments_mut()
        .map_err(|_| MailError::Configuration("invalid account link base"))?
        .pop_if_empty()
        .extend(["login", "magic-link"]);
    let fragment = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", token)
        .finish();
    link.set_fragment(Some(&fragment));
    Ok(link)
}

fn confirmation_message(
    from: &Mailbox,
    base: &Url,
    email: &ConfirmationEmail,
) -> Result<Message, MailError> {
    let link = confirmation_url(base, &email.token)?;
    let device = email
        .user_agent
        .as_deref()
        .unwrap_or("Unknown device")
        .replace(['\r', '\n'], " ");
    let address = email.ip.as_deref().unwrap_or("Unknown");
    let body = format!(
        "A password sign-in is awaiting confirmation. Compare this code with the code in your browser.\n\nCode: {}\nDevice: {device}\nIP address: {address}\n\nOpen this link to approve or decline the sign-in:\n{link}\n\nIf you did not start this sign-in, decline it and change your password.",
        email.match_code
    );
    Message::builder()
        .from(from.clone())
        .to(email.recipient.parse().map_err(|_| MailError::Message)?)
        .subject("Confirm your sign-in")
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|_| MailError::Message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email() -> ConfirmationEmail {
        ConfirmationEmail {
            recipient: "member@example.test".into(),
            token: "test-token".into(),
            match_code: "42".into(),
            ip: None,
            user_agent: None,
        }
    }

    #[test]
    fn account_base_prefers_explicit_mount_path_and_falls_back_to_login_origin() {
        let login = Some("https://login.example.test:8443/signin?lang=en".into());
        let base = account_base(
            Some("https://accounts.example.test/tenant/".into()),
            login.clone(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            confirmation_url(&base, "test-token").unwrap().as_str(),
            "https://accounts.example.test/tenant/login/magic-link#token=test-token"
        );
        assert_eq!(
            account_base(None, login).unwrap().unwrap().as_str(),
            "https://login.example.test:8443/"
        );
        assert!(account_base(None, None).unwrap().is_none());
        assert!(account_base(Some("mailto:admin@example.test".into()), None).is_err());
    }

    #[tokio::test]
    async fn mock_delivery_can_be_read_once() {
        let mailer = ConfirmationMailer {
            provider: Provider::Mock(Mutex::default()),
        };
        mailer.send(email()).await.unwrap();
        let messages = mailer.take_mock_messages().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].match_code, "42");
        assert!(mailer.take_mock_messages().unwrap().is_empty());
    }
}
