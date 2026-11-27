use super::*;
use axum::{Router, extract::Request, http::StatusCode, routing::post};
use serde_json::Value;

#[tokio::test]
async fn verifies_signed_data_and_both_certificate_statuses() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/storekit-verifier.json"
    ))
    .unwrap();
    let mut roots = X509StoreBuilder::new().unwrap();
    roots.set_flags(X509VerifyFlags::X509_STRICT).unwrap();
    roots
        .add_cert(cert(fixture["root"].as_str().unwrap(), None).unwrap())
        .unwrap();
    let failures = std::sync::Arc::new(std::sync::Mutex::new(("", "")));
    let router = Router::new().fallback(post({
        let fixture = fixture.clone();
        let failures = failures.clone();
        move |request: Request| {
            let path = request.uri().path().trim_start_matches('/');
            let (failed, kind) = *failures.lock().unwrap();
            let mode = if failed == path { kind } else { "good" };
            let response = fixture[format!("{path}_{mode}")]
                .as_str()
                .map(|v| STANDARD.decode(v).unwrap());
            async move {
                match response {
                    Some(bytes) => (StatusCode::OK, bytes),
                    None => (StatusCode::SERVICE_UNAVAILABLE, vec![]),
                }
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = reqwest::Proxy::all(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let verifier = Verifier {
        roots: roots.build(),
        http: reqwest::Client::builder().proxy(proxy).build().unwrap(),
    };
    let signed = fixture["signed"].as_str().unwrap();
    assert_eq!(
        verifier.decode::<Value>(signed).await.unwrap()["fixture"],
        true
    );
    for path in ["leaf", "issuer"] {
        for mode in ["revoked", "stale", "offline"] {
            *failures.lock().unwrap() = (path, mode);
            let err = verifier.decode::<Value>(signed).await.unwrap_err();
            assert_eq!(matches!(err, Fault::Unavailable), mode == "offline");
        }
    }
    *failures.lock().unwrap() = ("", "");
    assert!(
        verifier
            .decode::<Value>(fixture["wrong_purpose"].as_str().unwrap())
            .await
            .is_err()
    );
    let (header, rest) = signed.split_once('.').unwrap();
    let (_, signature) = rest.split_once('.').unwrap();
    let changed = format!(
        "{header}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(br#"{"fixture":false}"#)
    );
    assert!(verifier.decode::<Value>(&changed).await.is_err());
    task.abort();
}
