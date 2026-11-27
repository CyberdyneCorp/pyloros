set shell := ["sh", "-eu", "-c"]
export DATABASE_URL := env("DATABASE_URL", "postgresql://pyloros:local-development@127.0.0.1:" + env("PYLOROS_PG_PORT", "55432") + "/pyloros")
base_url := env("PYLOROS_URL", "http://127.0.0.1:8000")

# Show the available recipes.
default:
    @just --list

# Fetch the locked Rust dependencies.
setup:
    cargo fetch --locked
    cargo fetch --manifest-path hook-worker/Cargo.toml --locked

# Boot local PostgreSQL 17 and wait for it to accept connections.
db-up:
    docker compose up --detach --wait postgres

# Stop the local database and preserve its data volume.
db-down:
    docker compose stop postgres

# Open a SQL shell on the local database.
db-shell:
    docker compose exec postgres psql -U pyloros -d pyloros

# Run the API with the current environment.
run: hook-worker
    PYLOROS_HOOK_WORKER="${PYLOROS_HOOK_WORKER:-$PWD/hook-worker/target/debug/pyloros-hook-worker}" cargo run --locked

# Build the isolated component worker.
hook-worker:
    cargo build --manifest-path hook-worker/Cargo.toml --target-dir hook-worker/target --locked

# Build the sample Rust guest using cargo-component and the shared WIT.
build-hook-example:
    cargo component build --release --locked --target wasm32-unknown-unknown --target-dir target/hook-examples --manifest-path examples/event-name-hook/Cargo.toml

# Build the release backend and matching worker side by side.
build-release:
    cargo build --locked --release --bin pyloros
    cargo build --locked --release --manifest-path hook-worker/Cargo.toml --target-dir "${CARGO_TARGET_DIR:-target}"

# Boot the database, then run the API in the foreground.
dev: db-up run

# Format Rust source.
fmt:
    cargo fmt --all
    cargo fmt --manifest-path examples/event-name-hook/Cargo.toml
    cargo fmt --manifest-path hook-worker/Cargo.toml

# Check formatting and lint all targets.
lint:
    cargo fmt --manifest-path examples/event-name-hook/Cargo.toml -- --check
    cargo fmt --manifest-path hook-worker/Cargo.toml -- --check
    cargo clippy --manifest-path hook-worker/Cargo.toml --locked --all-targets -- -D warnings
    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings

# Run tests that do not require a database.
test:
    cargo test --manifest-path hook-worker/Cargo.toml --locked
    cargo test --locked

# Exercise readiness with real PostgreSQL using connection-local temporary tables.
test-db:
    cargo test --locked --tests -- --ignored

# Run the usual pre-commit checks.
check: lint test

# Check the running process and report its database readiness.
health:
    curl --fail-with-body --silent --show-error "{{base_url}}/api/v1/health"
    @echo
    curl --fail-with-body --silent --show-error "{{base_url}}/api/v1/health/ready"
    @echo

# Validate the project specifications with the OpenSpec CLI.
spec-check:
    openspec validate --all --strict

# Compare the five foundation routes on two running services.
[positional-arguments]
compare reference candidate *flags:
    python3 scripts/compare_foundation.py "$@"
