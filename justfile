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

# List deferrable PostgreSQL table constraints and triggers in application schemas.
db-commit-checks:
    uv run --script scripts/inspect_commit_checks.py

# Count account password prefixes on the target PostgreSQL database.
db-password-schemes:
    uv run --script scripts/account_password_schemes.py

# Check declared storage widths for verified Google Play purchase tokens.
db-play-token-width:
    uv run --script scripts/check_play_token_width.py

# Run the API with the current environment.
run: hook-worker
    PYLOROS_HOOK_WORKER="${PYLOROS_HOOK_WORKER:-$PWD/hook-worker/target/debug/pyloros-hook-worker}" cargo run --locked

# Build the isolated component worker.
hook-worker:
    cargo build --manifest-path hook-worker/Cargo.toml --target-dir hook-worker/target --locked

# Build the sample Rust guest using cargo-component and the shared WIT.
build-hook-example:
    cargo component build --release --locked --target wasm32-unknown-unknown --target-dir target/hook-examples --manifest-path examples/event-name-hook/Cargo.toml

# Execute all three compiled example components in the local worker.
check-hook-examples:
    cargo component build --locked --release --lib --examples --target wasm32-unknown-unknown --target-dir target/hook-examples --manifest-path examples/event-name-hook/Cargo.toml
    cargo build --locked --manifest-path hook-worker/Cargo.toml --target-dir hook-worker/target
    python3 scripts/check_hook_examples.py hook-worker/target/debug/pyloros-hook-worker target/hook-examples/wasm32-unknown-unknown/release

# Inspect one known transaction on the configured chain RPC endpoint.
[positional-arguments]
inspect-iam-receipt hash *flags:
    cargo run --quiet --locked -- --inspect-iam-receipt "$@"

# List hook bindings and check coverage for active definitions.
[positional-arguments]
hook-inventory *event:
    cargo run --quiet --locked -- --check-hook-bindings "$@"

# Require complete coverage and an exact match with the reviewed report.
[positional-arguments]
verify-hook-inventory reviewed *event:
    #!/bin/sh
    set -eu
    reviewed=$1
    shift
    current=$(mktemp)
    trap 'rm -f "$current"' EXIT
    just hook-inventory "$@" > "$current"
    cmp "$current" - < "$reviewed"

# Check how many committed component deliveries remain for these events.
[positional-arguments]
hook-queue *event:
    cargo run --quiet --locked -- --check-hook-queue "$@"

# Compare a candidate guest with a recorded outcome before uploading it.
[positional-arguments]
check-hook-fixture component event expected:
    cargo build --release --locked --manifest-path hook-worker/Cargo.toml --target-dir "${CARGO_TARGET_DIR:-target}"
    cargo run --release --locked --bin pyloros -- --check-hook-fixture "$@"

# Build the silent guest for hooks that produce no output or other effects.
build-silent-hook:
    cargo component build --release --locked --example silent_hook --target wasm32-unknown-unknown --target-dir target/hook-examples --manifest-path examples/event-name-hook/Cargo.toml

# Build the numeric counter guest.
build-counter-hook:
    cargo component build --release --locked --example counter_hook --target wasm32-unknown-unknown --target-dir target/hook-examples --manifest-path examples/event-name-hook/Cargo.toml

# Build the release backend and matching worker side by side.
build-release:
    cargo build --locked --release --bin pyloros
    cargo build --locked --release --manifest-path hook-worker/Cargo.toml --target-dir "${CARGO_TARGET_DIR:-target}"

# Boot the database, then run the API in the foreground.
dev: db-up run

# Format Rust source.
fmt:
    rustfmt --edition 2024 integrations/operator-cli/rebac.rs
    cargo fmt --all
    cargo fmt --manifest-path examples/event-name-hook/Cargo.toml
    cargo fmt --manifest-path hook-worker/Cargo.toml

# Check formatting and lint all targets.
lint:
    rustfmt --edition 2024 --check integrations/operator-cli/rebac.rs
    cargo fmt --manifest-path examples/event-name-hook/Cargo.toml -- --check
    cargo fmt --manifest-path hook-worker/Cargo.toml -- --check
    cargo clippy --manifest-path hook-worker/Cargo.toml --locked --all-targets -- -D warnings
    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings

# Run tests that do not require a database.
test:
    cargo test --locked --manifest-path examples/event-name-hook/Cargo.toml --lib --example counter_hook
    cargo test --manifest-path hook-worker/Cargo.toml --locked
    cargo test --locked

# Exercise readiness with real PostgreSQL using connection-local temporary tables.
test-db:
    cargo test --locked --tests -- --ignored

# Print the frontend build digest or compare it with the reviewed digest.
[positional-arguments]
check-frontend-build directory *expected:
    python3 scripts/check_frontend_build.py "$@"

# Record a packaged console runtime or compare it with a reviewed manifest.
[positional-arguments]
check-frontend-runtime directory *expected:
    python3 scripts/check_frontend_runtime.py "$@"

# Compare /app in local console builder and runtime images.
[positional-arguments]
check-frontend-image build_image runtime_image *expected:
    python3 scripts/check_frontend_image.py "$@"

# Start the shipped console command and check its login page on loopback.
[positional-arguments]
check-frontend-start runtime_image:
    python3 scripts/check_frontend_start.py "$@"

# Validate the published ReBAC contract and its JSON examples.
check-rebac-contract:
    uv run --script scripts/check_rebac_contract.py

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
    openspec validate --all --strict --no-interactive
    openspec validate --archived --strict --no-interactive

# Compare the five foundation routes on two running services.
[positional-arguments]
compare reference candidate *flags:
    python3 scripts/compare_foundation.py "$@"
