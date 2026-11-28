use super::*;
use std::process::Command;

// The child process inherits a fixture CA via OpenSSL's process-local trust settings.
#[tokio::test]
async fn trusted_receiver() {
    let Ok(port) = env::var("PYLOROS_TEST_TLS_PORT") else {
        let name = "webhook_worker::transport::tls_test::trusted_receiver";
        let status = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/webhook_tls.py"
            ))
            .arg(env::current_exe().unwrap())
            .arg(name)
            .status()
            .unwrap();
        assert!(status.success());
        return;
    };

    let isolated = env::var_os("PYLOROS_TEST_ISOLATED_NETWORK").is_some();
    let (address, hostname) = if isolated {
        ("192.0.0.9", "receiver.test")
    } else {
        ("127.0.0.1", "localhost")
    };
    let key = KeyEncryptionKey::new("fixture").unwrap();
    let subscription = Uuid::new_v4();
    let aad = format!("webhook-secret:{subscription}");
    let mut delivery = Delivery {
        id: Uuid::new_v4(),
        subscription,
        event: Uuid::nil(),
        body: r#"{"event":"fixture"}"#.into(),
        current: key
            .encrypt_with_aad(b"whsec_Zml4dHVyZQ==", aad.as_bytes())
            .unwrap(),
        previous: None,
        attempts: 0,
        url: format!("https://{address}:{port}/events"),
    };
    let settings = Settings {
        poll: Duration::from_secs(1),
        timeout: Duration::from_secs(5),
        lease: chrono::Duration::seconds(30),
        batch: 1,
        concurrency: 1,
        insecure: !isolated,
    };
    let refused = send(&delivery, Some(&key), Utc::now(), &settings).await;
    assert_eq!(refused.code, None);
    assert!(refused.error.unwrap().starts_with("ConnectError:"));

    if isolated {
        delivery.url = format!("https://127.0.0.1:{port}/events");
        let local = send(&delivery, Some(&key), Utc::now(), &settings).await;
        assert_eq!(local.code, None);
        assert_eq!(
            local.error.as_deref(),
            Some("destination refused: 127.0.0.1 resolves to a non-public address")
        );
    }
    delivery.url = format!("https://{hostname}:{port}/events");
    for (code, error) in [(503, Some("HTTP 503")), (202, None)] {
        let result = send(&delivery, Some(&key), Utc::now(), &settings).await;
        assert_eq!(result.code, Some(code), "{:?}", result.error);
        assert_eq!(result.error.as_deref(), error);
        assert_eq!(result.excerpt.as_deref(), Some("received"));
    }
}
