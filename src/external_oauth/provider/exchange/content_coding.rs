use super::*;
use axum::{
    Router,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response as HttpResponse},
    routing::{get, post},
};
use flate2::{
    Compression,
    write::{DeflateEncoder, GzEncoder, ZlibEncoder},
};
use std::io::Write;

const LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy)]
enum Coding {
    Identity,
    Gzip,
    Deflate,
    RawDeflate,
    IdentityGzip,
    IdentityRawDeflate,
    DoubleGzip,
    RawThenGzip,
}

fn encoded(document: &[u8], coding: Coding, headers: HeaderMap) -> HttpResponse {
    let (name, compressed) = match coding {
        Coding::DoubleGzip | Coding::RawThenGzip => {
            let inner = if matches!(coding, Coding::DoubleGzip) {
                let mut inner = GzEncoder::new(Vec::new(), Compression::fast());
                inner.write_all(document).unwrap();
                inner.finish().unwrap()
            } else {
                let mut inner = DeflateEncoder::new(Vec::new(), Compression::fast());
                inner.write_all(document).unwrap();
                inner.finish().unwrap()
            };
            let mut outer = GzEncoder::new(Vec::new(), Compression::fast());
            outer.write_all(&inner).unwrap();
            let mut response = outer.finish().unwrap().into_response();
            if matches!(coding, Coding::DoubleGzip) {
                response.headers_mut().insert(
                    header::CONTENT_ENCODING,
                    HeaderValue::from_static("gzip, gzip"),
                );
            } else {
                response.headers_mut().append(
                    header::CONTENT_ENCODING,
                    HeaderValue::from_static("deflate"),
                );
                response
                    .headers_mut()
                    .append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            }
            return response;
        }
        Coding::Identity => return document.to_owned().into_response(),
        Coding::Gzip | Coding::IdentityGzip => {
            let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(document).unwrap();
            ("gzip", enc.finish().unwrap())
        }
        Coding::RawDeflate | Coding::IdentityRawDeflate => {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(document).unwrap();
            ("deflate", enc.finish().unwrap())
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
    if matches!(coding, Coding::IdentityGzip) {
        response.headers_mut().insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity, gzip"),
        );
        return response;
    }
    if matches!(coding, Coding::IdentityRawDeflate) {
        response.headers_mut().append(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    }
    response
        .headers_mut()
        .append(header::CONTENT_ENCODING, HeaderValue::from_static(name));
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
    exchange_documents(kind, token, profile, token_doc, user_doc).await
}

async fn exchange_documents(
    kind: Kind,
    token: Coding,
    profile: Coding,
    token_doc: Vec<u8>,
    user_doc: Vec<u8>,
) -> Result<Profile, ExchangeError> {
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
    let codings = [
        Coding::Identity,
        Coding::Gzip,
        Coding::Deflate,
        Coding::RawDeflate,
        Coding::IdentityGzip,
        Coding::IdentityRawDeflate,
        Coding::DoubleGzip,
        Coding::RawThenGzip,
    ];
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
        for coding in [
            Coding::Gzip,
            Coding::Deflate,
            Coding::RawDeflate,
            Coding::IdentityGzip,
            Coding::IdentityRawDeflate,
            Coding::DoubleGzip,
            Coding::RawThenGzip,
        ] {
            assert_eq!(
                exchange(Kind::Google, coding, coding, token_len, profile_len)
                    .await
                    .is_ok(),
                accepted
            );
        }
    }
}

#[tokio::test]
async fn token_and_profile_decode_unicode_independently() {
    let token = r#"{"access_token":"example"}"#;
    let user = r#"{"id":"δοκιμή🌿","sub":"δοκιμή🌿"}"#;
    fn encodings(text: &str) -> Vec<Vec<u8>> {
        let representations: [(Vec<u8>, Vec<u8>); 5] = [
            (vec![0xef, 0xbb, 0xbf], text.as_bytes().to_vec()),
            (
                vec![0xff, 0xfe],
                text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            ),
            (
                vec![0xfe, 0xff],
                text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
            ),
            (
                vec![0xff, 0xfe, 0, 0],
                text.chars()
                    .flat_map(|c| u32::from(c).to_le_bytes())
                    .collect(),
            ),
            (
                vec![0, 0, 0xfe, 0xff],
                text.chars()
                    .flat_map(|c| u32::from(c).to_be_bytes())
                    .collect(),
            ),
        ];
        representations
            .into_iter()
            .flat_map(|(mut marker, bytes)| {
                marker.extend_from_slice(&bytes);
                [bytes, marker]
            })
            .collect()
    }
    let tokens = encodings(token);
    let profiles = encodings(user);
    for kind in [Kind::Google, Kind::Microsoft] {
        for token_bytes in &tokens {
            for user_bytes in &profiles {
                let account = exchange_documents(
                    kind,
                    Coding::Gzip,
                    Coding::Deflate,
                    token_bytes.clone(),
                    user_bytes.clone(),
                )
                .await
                .unwrap();
                assert_eq!(account.subject, "δοκιμή🌿");
            }
        }
    }
}

#[tokio::test]
async fn invalid_unicode_on_either_provider_endpoint_fails_the_exchange() {
    let broken = vec![0xff, 0xfe, b'{'];
    for (token, user) in [
        (broken.clone(), br#"{"sub":"subject"}"#.to_vec()),
        (br#"{"access_token":"example"}"#.to_vec(), broken),
    ] {
        assert!(
            exchange_documents(
                Kind::Google,
                Coding::Identity,
                Coding::Identity,
                token,
                user
            )
            .await
            .is_err()
        );
    }
}
