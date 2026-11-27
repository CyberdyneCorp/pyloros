use pyloros::webhook_worker::Worker;
use sqlx::postgres::PgPoolOptions;
use std::{env, process::Command};

#[tokio::test]
async fn webhook_worker_startup_policy() {
    // Each case gets a separate environment, including when other tests run concurrently.
    if let Ok(expected) = env::var("TEST_EXPECT_WEBHOOK_WORKER") {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/pyloros")
            .unwrap();
        let started = Worker::start(pool);
        match expected.as_str() {
            "started" => assert!(matches!(started, Ok(Some(_)))),
            "stopped" => assert!(matches!(started, Ok(None))),
            "invalid" => assert!(started.is_err()),
            _ => unreachable!(),
        }
        return;
    }

    for (global, local, expected) in [
        ("true", None, "started"),
        ("true", Some("true"), "started"),
        ("true", Some("false"), "stopped"),
        ("false", Some("true"), "stopped"),
        ("true", Some("invalid"), "invalid"),
    ] {
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .args(["--exact", "webhook_worker_startup_policy"])
            .env_clear()
            .env("WEBHOOKS_ENABLED", global)
            .env("TEST_EXPECT_WEBHOOK_WORKER", expected);
        if let Some(value) = local {
            command.env("PYLOROS_WEBHOOK_WORKER_ENABLED", value);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "global={global}, local={local:?}: {}",
            String::from_utf8_lossy(&result.stdout)
        );
    }
}
