use pyloros::{profile::ComponentHookWorker, webhook_worker::Worker};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, process::Command};

fn pool() -> PgPool {
    PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/pyloros")
        .unwrap()
}

fn check_result<T, E>(started: Result<Option<T>, E>, expected: &str) {
    match expected {
        "started" => assert!(matches!(started, Ok(Some(_)))),
        "stopped" => assert!(matches!(started, Ok(None))),
        "invalid" => assert!(started.is_err()),
        _ => unreachable!(),
    }
}

fn run_case(name: &str, settings: &[(&str, Option<&str>)], expected: &str) {
    // Isolate process-wide configuration even when tests run concurrently.
    let mut command = Command::new(env::current_exe().unwrap());
    command
        .args(["--exact", name])
        .env_clear()
        .env("TEST_EXPECT_WORKER", expected);
    for (key, value) in settings {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{settings:?}: {}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[tokio::test]
async fn webhook_worker_startup_policy() {
    if let Ok(expected) = env::var("TEST_EXPECT_WORKER") {
        return check_result(Worker::start(pool()), &expected);
    }
    for (global, local, expected) in [
        ("true", None, "started"),
        ("true", Some("true"), "started"),
        ("true", Some("false"), "stopped"),
        ("false", Some("true"), "stopped"),
        ("true", Some("invalid"), "invalid"),
    ] {
        run_case(
            "webhook_worker_startup_policy",
            &[
                ("WEBHOOKS_ENABLED", Some(global)),
                ("PYLOROS_WEBHOOK_WORKER_ENABLED", local),
            ],
            expected,
        );
    }
}

#[tokio::test]
async fn component_worker_startup_policy() {
    if let Ok(expected) = env::var("TEST_EXPECT_WORKER") {
        return check_result(ComponentHookWorker::start(pool()), &expected);
    }
    for (global, producer, local, expected) in [
        ("true", "false", None, "stopped"),
        ("true", "true", None, "started"),
        ("true", "true", Some("false"), "stopped"),
        ("true", "false", Some("true"), "started"),
        ("false", "true", Some("true"), "stopped"),
        ("true", "true", Some("invalid"), "invalid"),
    ] {
        run_case(
            "component_worker_startup_policy",
            &[
                ("HOOKS_ENABLED", Some(global)),
                ("PYLOROS_REGISTRATION_HOOK_DISPATCH", Some(producer)),
                ("PYLOROS_COMPONENT_WORKER_ENABLED", local),
            ],
            expected,
        );
    }
}
