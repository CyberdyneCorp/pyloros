use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::hmac;
use std::time::Instant;
use zeroize::Zeroizing;

fn signatures(
    delivery: &Delivery,
    key: &KeyEncryptionKey,
    message: &str,
    stamp: i64,
) -> Option<String> {
    let aad = format!("webhook-secret:{}", delivery.subscription);
    let prefix = format!("{message}.{stamp}.");
    let mut signatures = Vec::new();
    for envelope in std::iter::once(&delivery.current).chain(delivery.previous.iter()) {
        let secret = key.decrypt_with_aad(envelope, aad.as_bytes()).ok()?;
        let encoded = secret.strip_prefix(b"whsec_").unwrap_or(&secret);
        let bytes = Zeroizing::new(STANDARD.decode(encoded).ok()?);
        let mut mac = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, &bytes));
        mac.update(prefix.as_bytes());
        mac.update(delivery.body.as_bytes());
        signatures.push(format!("v1,{}", STANDARD.encode(mac.sign().as_ref())));
    }
    Some(signatures.join(" "))
}

pub(super) async fn send(
    d: &Delivery,
    key: Option<&KeyEncryptionKey>,
    at: DateTime<Utc>,
    settings: &Settings,
) -> Attempt {
    let message = format!("msg_{}", d.event.simple());
    let stamp = at.timestamp();
    let Some(signature) = key.and_then(|k| signatures(d, k, &message, stamp)) else {
        return Attempt::failed("signing secret unavailable".into());
    };
    let start = Instant::now();
    let mut attempt = match tokio::time::timeout(
        settings.timeout,
        post(d, &message, stamp, signature, settings),
    )
    .await
    {
        Ok(Ok(attempt)) => attempt,
        Ok(Err(error)) => Attempt::failed(error),
        Err(_) => Attempt::failed(format!("timeout after {}s", settings.timeout.as_secs_f64())),
    };
    attempt.duration_ms = i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX);
    attempt
}

async fn post(
    d: &Delivery,
    message: &str,
    stamp: i64,
    signature: String,
    settings: &Settings,
) -> Result<Attempt, String> {
    let bad = "destination refused: scheme or host not allowed";
    let mut url = url::Url::parse(&d.url).map_err(|e| match e {
        url::ParseError::InvalidPort => "destination refused: invalid port".into(),
        _ => bad.to_owned(),
    })?;
    if !(url.scheme() == "https" || settings.insecure && url.scheme() == "http")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(bad.into());
    }
    url.set_fragment(None);
    let host = url.host_str().ok_or(bad)?.trim_matches(['[', ']']);
    let port = url.port_or_known_default().ok_or(bad)?;
    let unresolved = || format!("destination refused: cannot resolve {host}");
    let mut answers = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| unresolved())?
        .peekable();
    if answers.peek().is_none() {
        return Err(unresolved());
    }
    let address = if settings.insecure {
        answers.next()
    } else {
        crate::hook_egress::pin(answers)
    }
    .ok_or_else(|| format!("destination refused: {host} resolves to a non-public address"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_deflate()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(host, address)
        .build()
        .map_err(http_error)?;
    let mut request = client
        .post(url.clone())
        .header("accept-encoding", "gzip, deflate")
        .header("content-type", "application/json")
        .header(
            "user-agent",
            concat!("CyberdyneAuth-Webhooks/", env!("CARGO_PKG_VERSION")),
        )
        .header("webhook-id", message)
        .header("webhook-timestamp", stamp.to_string())
        .header("webhook-signature", signature)
        .body(d.body.clone());
    if let Ok(uri) = d.url.parse::<axum::http::Uri>()
        && let Some(authority) = uri.authority()
        && !authority.as_str().contains('@')
    {
        request = request.header("host", authority.as_str());
    }
    let response = request.send().await.map_err(http_error)?;
    let code = i32::from(response.status().as_u16());
    let excerpt = receiver_excerpt(response).await?;
    Ok(Attempt {
        code: Some(code),
        duration_ms: 0,
        excerpt: Some(String::from_utf8_lossy(&excerpt).into_owned()),
        error: (!(200..300).contains(&code)).then(|| format!("HTTP {code}")),
    })
}

async fn receiver_excerpt(response: reqwest::Response) -> Result<Vec<u8>, String> {
    crate::http_body::read(response, crate::http_body::ReadLimit::Prefix(1024))
        .await
        .map_err(|error| {
            match error
                .get_ref()
                .and_then(|e| e.downcast_ref::<crate::http_body::ShortBody>())
            {
                Some(short) => format!("RemoteProtocolError: {short}"),
                None => "ReadError: response unavailable".to_owned(),
            }
        })
}

fn http_error(error: reqwest::Error) -> String {
    if error.is_connect() {
        let mut cause = error.source();
        while let Some(current) = cause {
            if current
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
            {
                return "ConnectError: All connection attempts failed".into();
            }
            cause = current.source();
        }
        "ConnectError: connection failed".into()
    } else {
        "ReadError: response unavailable".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_cover_exact_body_with_both_keys_and_bind_to_subscription() {
        let key = KeyEncryptionKey::new("independent fixture for signing").unwrap();
        let subscription = Uuid::new_v4();
        let aad = format!("webhook-secret:{subscription}");
        let seal = |value: &str| {
            key.encrypt_with_aad(value.as_bytes(), aad.as_bytes())
                .unwrap()
        };
        let mut d = Delivery {
            id: Uuid::new_v4(),
            subscription,
            event: Uuid::nil(),
            url: "https://example.test".into(),
            body: r#"{"δ":1}"#.into(),
            attempts: 0,
            current: seal("whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
            previous: Some(seal("whsec_Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=")),
        };
        let message = format!("msg_{}", d.event.simple());
        assert_eq!(
            signatures(&d, &key, &message, 1234).unwrap(),
            "v1,t3FC773JKwWdtMzZBZ42wjrSbNdakoNCRzXSyQYafEY= v1,Rg/c2Z7/wto0CYkkCrZTAr6myooI5qG6tnlauDOY5IU="
        );
        d.subscription = Uuid::new_v4();
        assert!(signatures(&d, &key, &message, 1234).is_none());
    }

    #[tokio::test]
    async fn short_fixed_length_body_reports_byte_counts_until_the_excerpt_is_full() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for size in [0, 1023, 1024] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let receiver = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0u8; 4096];
                let _ = socket.read(&mut request).await.unwrap();
                let mut reply = b"HTTP/1.1 202 Accepted\r\nContent-Length: 1100\r\n\r\n".to_vec();
                reply.extend(vec![b'x'; size]);
                socket.write_all(&reply).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .post(format!("http://{address}"))
                .send()
                .await
                .unwrap();
            let result = receiver_excerpt(response).await;
            receiver.await.unwrap();
            if size == 1024 {
                assert_eq!(result.unwrap(), vec![b'x'; size]);
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    format!(
                        "RemoteProtocolError: peer closed connection without sending complete message body (received {size} bytes, expected 1100)"
                    )
                );
            }
        }
    }

    #[tokio::test]
    async fn short_encoded_body_reports_wire_bytes_for_single_and_stacked_codings() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut compressed = vec![b'x'; 1023];
        for coding in ["gzip", "gzip, gzip"] {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&compressed).unwrap();
            compressed = encoder.finish().unwrap();
            let size = compressed.len();
            let expected = size + 40;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut reply = format!("HTTP/1.1 503 Busy\r\nContent-Encoding: {coding}\r\nContent-Length: {expected}\r\n\r\n").into_bytes();
            reply.extend_from_slice(&compressed);
            let receiver = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let _ = socket.read(&mut [0; 4096]).await.unwrap();
                socket.write_all(&reply).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let response = reqwest::Client::builder()
                .no_proxy()
                .no_gzip()
                .build()
                .unwrap()
                .get(format!("http://{address}"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                receiver_excerpt(response).await.unwrap_err(),
                format!(
                    "RemoteProtocolError: peer closed connection without sending complete message body (received {size} bytes, expected {expected})"
                )
            );
            receiver.await.unwrap();
        }
    }

    #[tokio::test]
    async fn receiver_gets_signed_headers_and_redirect_is_recorded_with_a_bounded_excerpt() {
        use axum::{
            Router,
            http::{HeaderMap, StatusCode},
            routing::post as route_post,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/notify",
            route_post(
                |uri: axum::extract::OriginalUri, headers: HeaderMap, body: String| async move {
                    assert_eq!(body, "{}");
                    assert_eq!(headers["webhook-signature"], "v1,test");
                    assert_eq!(headers["webhook-timestamp"], "123");
                    assert_eq!(headers["webhook-id"], "msg_test");
                    let gzip = STANDARD
                        .decode("H4sIAAAAAAAC/zu3+9woHIWjcBSOwlFIMgQAQxwPwUAGAAA=")
                        .unwrap();
                    let (coding, encoded) = match uri.query() {
                        Some("raw") => ("deflate", gzip[10..gzip.len() - 8].to_vec()),
                        Some("flushed") => (
                            "gzip",
                            STANDARD.decode("H4sIAAAAAAAAEyrOyC8qAQAAAP//").unwrap(),
                        ),
                        _ => ("gzip", gzip),
                    };
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [("location", "/other"), ("content-encoding", coding)],
                        encoded,
                    )
                },
            ),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut d = Delivery {
            id: Uuid::new_v4(),
            event: Uuid::new_v4(),
            subscription: Uuid::new_v4(),
            body: "{}".into(),
            url: format!("http://{address}/notify"),
            attempts: 0,
            current: vec![],
            previous: None,
        };
        let mut settings = Settings {
            poll: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            lease: chrono::Duration::seconds(31),
            batch: 1,
            concurrency: 1,
            insecure: true,
        };
        let result = post(&d, "msg_test", 123, "v1,test".into(), &settings)
            .await
            .unwrap();
        assert_eq!(result.code, Some(307));
        assert_eq!(result.error.as_deref(), Some("HTTP 307"));
        assert_eq!(result.excerpt.unwrap(), "λ".repeat(512));
        d.url.push_str("?raw");
        let result = post(&d, "msg_test", 123, "v1,test".into(), &settings)
            .await
            .unwrap();
        assert_eq!(result.code, Some(307));
        assert_eq!(result.excerpt.unwrap(), "λ".repeat(512));
        d.url = format!("http://{address}/notify?flushed");
        let result = post(&d, "msg_test", 123, "v1,test".into(), &settings)
            .await
            .unwrap();
        assert_eq!(result.code, Some(307));
        assert_eq!(result.excerpt.as_deref(), Some("short"));
        settings.insecure = false;
        assert!(
            post(&d, "msg_test", 123, "v1,test".into(), &settings)
                .await
                .is_err()
        );
        server.abort();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tls_test;
