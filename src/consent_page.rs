//! Render the deployment's shared consent artifact with a short-lived, signed form ticket.
use crate::{browser_client::BrowserClient, consent_http, grant_sessions::GrantSessionIssuer};
use axum::{
    http::header,
    response::{Html, IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use minijinja::{Environment, UndefinedBehavior, context};
use serde::Deserialize;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use std::{collections::BTreeMap, env, error::Error, fs};
use uuid::Uuid;

#[derive(Deserialize)]
struct Bundle {
    template: String,
    descriptions: BTreeMap<String, String>,
}

pub(crate) struct Page {
    templates: Environment<'static>,
    descriptions: BTreeMap<String, String>,
}

pub(crate) struct Approval<'a> {
    pub client: &'a BrowserClient,
    pub user: Uuid,
    pub resource: &'a str,
    pub scopes: &'a str,
    pub query: &'a str,
}

type PageError = Box<dyn Error + Send + Sync>;

pub(crate) fn html_environment() -> Environment<'static> {
    let mut templates = Environment::new();
    templates.set_undefined_behavior(UndefinedBehavior::Strict);
    templates.set_formatter(|out, _, value| {
        let text = value.to_string();
        let escaped = text
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;");
        out.write_str(&escaped)?;
        Ok(())
    });
    templates
}

async fn scope_items(
    tx: &mut Transaction<'_, Postgres>,
    catalog: &BTreeMap<String, String>,
    raw: &str,
) -> Result<Vec<minijinja::Value>, sqlx::Error> {
    let names: Vec<_> = raw.split_whitespace().collect();
    let custom: Vec<_> = names
        .iter()
        .copied()
        .filter(|s| !catalog.contains_key(*s))
        .collect();
    let mut descriptions = BTreeMap::new();
    if !custom.is_empty() {
        descriptions = sqlx::query_as::<_, (String, String)>(
            "SELECT name,description FROM oauth_scopes WHERE active AND name=ANY($1)",
        )
        .bind(&custom)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .collect();
    }
    Ok(names
        .iter()
        .map(|&name| {
            let description = catalog.get(name).or_else(|| descriptions.get(name));
            context! {name, description => description.map_or("",String::as_str)}
        })
        .collect())
}

pub(crate) fn sign_ticket(
    signer: &GrantSessionIssuer,
    user: Uuid,
    client: &str,
    resource: &str,
    scopes: &str,
    query: &str,
    now: DateTime<Utc>,
) -> Result<String, PageError> {
    Ok(signer.sign(&json!({
        "iss": signer.issuer(),
        "sub": user,
        "jti": Uuid::new_v4(),
        "type": "consent",
        "client_id": client,
        "resource": resource,
        "scope": scopes,
        "authz": query,
        "iat": now.timestamp(),
        "exp": now.timestamp() + 600,
    }))?)
}

pub(crate) fn html_response(status: axum::http::StatusCode, html: String) -> Response {
    let headers = [
        (header::CACHE_CONTROL, "no-store"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    ];
    (status, headers, Html(html)).into_response()
}

impl Page {
    pub(crate) fn configured() -> Result<Option<Self>, Box<dyn Error>> {
        let Some(path) = env::var_os("PYLOROS_CONSENT_UI_PATH") else {
            return Ok(None);
        };
        let bundle: Bundle = serde_json::from_slice(&fs::read(path)?)?;
        Ok(Some(Self::new(bundle)?))
    }

    fn new(bundle: Bundle) -> Result<Self, minijinja::Error> {
        let mut templates = html_environment();
        templates.add_template_owned("consent", bundle.template)?;
        Ok(Self {
            templates,
            descriptions: bundle.descriptions,
        })
    }

    pub(crate) async fn render(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        signer: &GrantSessionIssuer,
        approval: Approval<'_>,
        now: DateTime<Utc>,
    ) -> Result<Response, PageError> {
        let client = approval.client;
        let scopes = scope_items(tx, &self.descriptions, approval.scopes).await?;
        let ticket = sign_ticket(
            signer,
            approval.user,
            &client.id,
            approval.resource,
            approval.scopes,
            approval.query,
            now,
        )?;
        let host = client
            .callback
            .split_once("://")
            .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
            .filter(|host| !host.is_empty())
            .unwrap_or(&client.callback);
        let html = self.templates.get_template("consent")?.render(context! {
            client_name => client.name,
            client_id => client.id,
            self_registered => client.dynamic,
            redirect_host => host,
            resource => approval.resource,
            scopes, ticket, action => consent_http::PATH,
        })?;
        Ok(html_response(axum::http::StatusCode::OK, html))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interpolated_values_are_escaped_once_and_never_evaluated_as_template_code() {
        let page = Page::new(Bundle {
            template: "{{ client_name }}".into(),
            descriptions: BTreeMap::new(),
        })
        .unwrap();
        let rendered = page
            .templates
            .get_template("consent")
            .unwrap()
            .render(context! {client_name=>"<>&'\"{{ ticket }}"})
            .unwrap();
        assert_eq!(rendered, "&lt;&gt;&amp;&#x27;&quot;{{ ticket }}");
    }
}
