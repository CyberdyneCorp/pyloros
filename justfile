set shell := ["sh", "-eu", "-c"]
export DATABASE_URL := env("DATABASE_URL", "postgresql://pyloros:local-development@127.0.0.1:" + env("PYLOROS_PG_PORT", "55432") + "/pyloros")
base_url := env("PYLOROS_URL", "http://127.0.0.1:8000")

# Show the available recipes.
default:
    @just --list

# Fetch the locked Rust dependencies.
setup:
    cargo fetch --locked

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
run:
    cargo run --locked

# Boot the database, then run the API in the foreground.
dev: db-up run

# Format Rust source.
fmt:
    cargo fmt --all

# Check formatting and lint all targets.
lint:
    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings

# Run tests that do not require a database.
test:
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
