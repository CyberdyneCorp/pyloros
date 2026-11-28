use super::*;
use axum::{
    Router,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response as HttpResponse},
    routing::{get, post},
};
use flate2::{
    Compression,
    write::{GzEncoder, ZlibEncoder},
};
use std::io::Write;

const LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy)]
enum Coding {
    Identity,
    Gzip,
    Deflate,
}

fn encoded(document: &[u8], coding: Coding, headers: HeaderMap) -> HttpResponse {
    let (name, compressed) = match coding {
        Coding::Identity => return document.to_owned().into_response(),
        Coding::Gzip => {
            let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(document).unwrap();
            ("gzip", enc.finish().unwrap())
        }
        Coding::Deflate => {
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(document).unwrap();
            ("deflate", enc.finish().unwrap())
        }
    };
    assert!(
        headers[header::ACCEPT_ENCODING]
            .to_str()
            .unwrap()
            .split(',')
            .any(|encoding| encoding.trim() == name)
    );
    let mut response = compressed.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static(name));
    response
}

async fn exchange(
    kind: Kind,
    token: Coding,
    profile: Coding,
    token_len: usize,
    profile_len: usize,
) -> Result<Profile, ExchangeError> {
    let mut token_doc = br#"{"access_token":"example"}"#.to_vec();
    token_doc.resize(token_len.max(token_doc.len()), b' ');
    let mut user_doc = br#"{"id":"account","sub":"account"}"#.to_vec();
    user_doc.resize(profile_len.max(user_doc.len()), b' ');
    let app = Router::new()
        .route(
            "/token",
            post(move |headers: HeaderMap| async move { encoded(&token_doc, token, headers) }),
        )
        .route(
            "/profile",
            get(move |headers: HeaderMap| async move { encoded(&user_doc, profile, headers) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let remote = Remote {
        kind,
        id: "example".into(),
        secret: "example".to_owned().into(),
        callback: format!("{origin}/callback"),
        authorization: String::new(),
        token: format!("{origin}/token"),
        profile: format!("{origin}/profile"),
        http: super::super::provider_http()
            .https_only(false)
            .no_proxy()
            .build()
            .unwrap(),
    };
    let result = remote.exchange("example").await;
    server.abort();
    result
}

#[tokio::test]
async fn provider_documents_can_use_independent_content_codings() {
    let codings = [Coding::Identity, Coding::Gzip, Coding::Deflate];
    for kind in [Kind::Google, Kind::Microsoft] {
        for token in codings {
            for profile in codings {
                let account = exchange(kind, token, profile, 0, 0).await.unwrap();
                assert_eq!(account.subject, "account");
            }
        }
    }
}

#[tokio::test]
async fn limit_applies_to_each_decoded_provider_document() {
    for (token_len, profile_len, accepted) in [
        (LIMIT, LIMIT, true),
        (LIMIT + 1, 0, false),
        (0, LIMIT + 1, false),
    ] {
        assert_eq!(
            exchange(
                Kind::Google,
                Coding::Gzip,
                Coding::Deflate,
                token_len,
                profile_len
            )
            .await
            .is_ok(),
            accepted
        );
    }
}
