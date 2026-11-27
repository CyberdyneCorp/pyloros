//! Provision operator-managed OAuth clients in the shared registry.
use super::*;
use crate::{
    browser_prompt::{quoted_list, quoted_string},
    passwords::PasswordScheme,
};
use metadata::Metadata;
use std::collections::BTreeMap;

fn parse_authority(raw: &str) -> Option<axum::http::uri::Authority> {
    if raw.is_ascii() {
        return raw.parse().ok();
    }
    let (host, port) = raw.split_once(':').unwrap_or((raw, ""));
    let name = url::Host::parse(host).ok()?;
    format!("{name}:{port}").parse().ok()
}

pub(super) fn redirect(uri: &str, kind: &str, clean: bool) -> Result<(), String> {
    let quoted = quoted_string(uri);
    let parts = uri.split_once(':');
    let (scheme, rest) = parts.unwrap_or(("", ""));
    let raw = rest
        .strip_prefix("//")
        .map(|s| s.split(['/', '?', '#']).next().unwrap_or(""));
    let bad_form = || format!("redirect_uri must not carry userinfo or a fragment: {quoted}");
    if clean
        && (uri
            .split_once('#')
            .is_some_and(|(_, frag)| !frag.is_empty())
            || raw.is_some_and(|s| s.contains('@')))
    {
        return Err(bad_form());
    }
    let authority = raw
        .filter(|v| !v.is_empty())
        .and_then(|v| v.rsplit('@').next())
        .and_then(parse_authority);
    if clean
        && raw.is_some_and(|v| !v.is_empty())
        && authority.as_ref().is_none_or(|a| {
            let port = &a.as_str()[a.host().len()..];
            port.len() > 1 && a.port_u16().is_none()
        })
    {
        return Err(bad_form());
    }
    let host = authority
        .as_ref()
        .map(|a| a.host().to_ascii_lowercase())
        .unwrap_or_default();
    let public = kind == "public";
    let accepted = match scheme.to_ascii_lowercase().as_str() {
        "https" => !host.is_empty(),
        "http" => {
            raw.is_some_and(str::is_ascii)
                && matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
        }
        _ => {
            public
                && url::Url::parse(uri).is_ok()
                && !rest
                    .trim_start_matches("//")
                    .split(['?', '#'])
                    .next()
                    .unwrap_or("")
                    .is_empty()
        }
    };
    if accepted {
        return Ok(());
    }
    let policy = if public {
        "public client redirect_uri must be https, loopback http (http://127.0.0.1 / http://localhost / http://[::1], any port), or a private-use URI scheme (RFC 8252)"
    } else {
        "confidential client redirect_uri must be https or loopback http"
    };
    Err(format!("{policy}: {quoted}"))
}

fn validate(m: &Metadata, scopes: &BTreeMap<String, String>) -> Result<(), String> {
    validate_scopes(&m.scopes, scopes)?;
    validate_audience(m.audience.as_deref())?;
    validate_grants(&m.grants)?;
    redirects(
        &m.kind,
        m.grants.contains("authorization_code"),
        m.redirects.as_ref(),
        m.logout.as_ref(),
        true,
    )
}

pub(super) fn redirects(
    kind: &str,
    code_grant: bool,
    registered: Option<&BTreeSet<String>>,
    logout: Option<&BTreeSet<String>>,
    supplied: bool,
) -> Result<(), String> {
    if supplied || code_grant {
        for uri in registered.into_iter().flatten() {
            redirect(uri, kind, supplied)?;
        }
    }
    if code_grant && registered.is_none_or(BTreeSet::is_empty) {
        return Err("authorization_code grant requires at least one redirect_uri".into());
    }
    for uri in logout.into_iter().flatten() {
        redirect(uri, kind, false)?;
    }
    Ok(())
}
pub(in crate::profile) fn validate_scopes(
    requested: &BTreeSet<String>,
    scopes: &BTreeMap<String, String>,
) -> Result<(), String> {
    let unknown: Vec<_> = requested
        .iter()
        .filter(|s| !scopes.contains_key(*s))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return Err(format!("unknown scopes: {}", quoted_list(&unknown)));
    }
    Ok(())
}
pub(super) fn validate_audience(audience: Option<&str>) -> Result<(), String> {
    if audience.is_some_and(|s| {
        s.is_empty() || s.chars().count() > 255 || s.chars().any(char::is_whitespace)
    }) {
        return Err("access_token_audience must be 1-255 characters with no whitespace".into());
    }
    Ok(())
}
pub(super) fn validate_grants(grants: &BTreeSet<String>) -> Result<(), String> {
    let unknown: Vec<_> = grants
        .iter()
        .map(String::as_str)
        .filter(|s| {
            !matches!(
                *s,
                "client_credentials"
                    | "refresh_token"
                    | "authorization_code"
                    | "urn:ietf:params:oauth:grant-type:device_code"
            )
        })
        .collect();
    if !unknown.is_empty() {
        return Err(format!("unknown grant_types: {}", quoted_list(&unknown)));
    }
    Ok(())
}
fn joined(set: &BTreeSet<String>) -> String {
    set.iter().map(String::as_str).collect::<Vec<_>>().join(" ")
}

pub(super) async fn apply(
    state: &Profile,
    mut tx: Transaction<'_, Postgres>,
    actor: (Uuid, Option<&str>),
    body: Option<Value>,
    origin: SessionOrigin<'_>,
) -> Result<Response, sqlx::Error> {
    let Some(body) = body else {
        return Ok(internal());
    };
    let m = match Metadata::parse(body) {
        Ok(m) => m,
        Err(issues) => {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":issues})),
            )
                .into_response());
        }
    };
    let Some(scopes) = state.client_scopes.get() else {
        return Ok(internal());
    };
    if let Err(msg) = validate(&m, &scopes.catalog.borrow()) {
        return Ok(problem(StatusCode::BAD_REQUEST, &msg));
    }
    let client_id = format!("cyb_{}", crate::client_auth::opaque::<12>());
    let secret = crate::client_auth::opaque::<32>();
    let hash = PasswordScheme::Argon2
        .hash(secret.clone())
        .await
        .map_err(|_| sqlx::Error::WorkerCrashed)?;
    let row=sqlx::query(&format!("INSERT INTO oauth_clients (id,client_id,secret_hash,name,description,allowed_scopes,allowed_audiences,max_token_ttl_s,
         grant_types,client_type,redirect_uris,post_logout_redirect_uris,access_token_audience,trusted,created_by_user_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING {COLUMNS}"))
        .bind(Uuid::new_v4()).bind(&client_id).bind(hash).bind(&m.name).bind(m.description).bind(joined(&m.scopes)).bind(json!(m.audiences)).bind(m.ttl)
        .bind(joined(&m.grants)).bind(&m.kind).bind(json!(m.redirects)).bind(json!(m.logout)).bind(m.audience).bind(m.trusted).bind(actor.0).fetch_one(&mut *tx).await?;
    let client = item(row)?;
    crate::admin_audit::append_client_action(
        &mut tx,
        "oauth_client.create",
        Some(actor),
        &client_id,
        json!({"name":m.name,"client_type":m.kind}),
        origin,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"client":client,"client_secret":secret})),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_redirects_require_a_public_client_and_an_actual_target() {
        assert!(redirect("com.example.app:/signin", "public", true).is_ok());
        assert!(redirect("https://münchen.example:8443/cb", "confidential", true).is_ok());
        assert!(redirect("http://ｌｏｃａｌｈｏｓｔ/cb", "public", true).is_err());
        assert!(redirect("com.example.app:/signin", "confidential", true).is_err());
        assert!(redirect("com.example.app:", "public", true).is_err());
        for uri in [
            "https://user@app.example/cb",
            "https://app.example:99999/cb",
            "https://app.example/cb#token",
            "http://127.1/cb",
        ] {
            assert!(redirect(uri, "public", true).is_err(), "{uri}");
        }
    }
}
