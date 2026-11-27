//! Format transport failures for operator-visible provider outcomes.
use super::ReadError;
use crate::browser_prompt::quoted_string;
use std::{error::Error, net::IpAddr};

pub(super) fn http_error(endpoint: &str, response: &reqwest::Response) -> ReadError {
    let status = response.status();
    let reason = response
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .and_then(|r| std::str::from_utf8(r.as_bytes()).ok())
        .or_else(|| status.canonical_reason())
        .unwrap_or_default();
    let mut url = response.url().clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_fragment(None);
    let rendered = url.as_str();
    let rendered = if url.path() == "/" && url.query().is_none() && !endpoint.ends_with('/') {
        rendered.trim_end_matches('/')
    } else {
        rendered
    };
    ReadError::Transport(Some(format!(
        "{}, message={}, url={}",
        status.as_u16(),
        quoted_string(reason),
        quoted_string(rendered)
    )))
}

pub(super) fn request_error(endpoint: &str, error: &reqwest::Error) -> ReadError {
    if error.is_timeout() {
        return ReadError::Transport(Some(String::new()));
    }
    let mut cause = error.source();
    while let Some(inner) = cause {
        if let Some(io) = inner.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::ConnectionRefused
        {
            return ReadError::Transport(refused(endpoint));
        }
        if let Some(http) = inner.downcast_ref::<hyper::Error>()
            && http.is_incomplete_message()
        {
            return ReadError::Transport(Some("Server disconnected".into()));
        }
        cause = inner.source();
    }
    ReadError::Transport(None)
}

fn refused(endpoint: &str) -> Option<String> {
    let url = reqwest::Url::parse(endpoint).ok()?;
    let ip: IpAddr = url.host_str()?.trim_matches(['[', ']']).parse().ok()?;
    let port = url.port_or_known_default()?;
    let peer = match ip {
        IpAddr::V4(_) => format!("('{ip}', {port})"),
        IpAddr::V6(_) => format!("('{ip}', {port}, 0, 0)"),
    };
    Some(format!(
        "Cannot connect to host {ip}:{port} ssl:default [Connect call failed {peer}]"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn http_failure_uses_the_provider_reason_and_url() {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/chain", socket.local_addr().unwrap());
        let serve = tokio::spawn(async move {
            let (mut stream, _) = socket.accept().await.unwrap();
            let mut lines = BufReader::new(&mut stream).lines();
            while lines
                .next_line()
                .await
                .unwrap()
                .is_some_and(|line| !line.is_empty())
            {}
            stream
                .write_all(b"HTTP/1.1 429 Fixture busy\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let response = reqwest::get(&url).await.unwrap();
        let ReadError::Transport(Some(detail)) = http_error(&url, &response) else {
            panic!("expected HTTP failure")
        };
        assert_eq!(detail, format!("429, message='Fixture busy', url='{url}'"));
        serve.await.unwrap();
    }
}
