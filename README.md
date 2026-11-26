# Pyloros

Pyloros is a planned identity and authorization service with a Rust backend. Applications will use it to sign people in and decide what they can do. The first Rust service exposes liveness and database readiness probes.

## Authorization

Role-based access control (RBAC) will let an application assign permissions to roles. For example, a reviewer might be allowed to approve submissions for one organization.

Relationship-based access control (ReBAC) will let an application grant access through relationships between people and resources. A reviewer might be allowed to open a particular submission because it belongs to a collection shared with their team. Applications can require both the reviewer role and access to that submission.

## Compatibility goals

The design starts from the experience of application developers, users and operators. Priorities include interoperable sign-in and token handling, account and session management, administrative tools, auditability, and reliable integration events. Compatibility will be assessed through observable behavior and migration tests as the service develops.

## Extension hooks

The proposed hook runtime is WebAssembly, hosted by Rust. Existing scripts would be ported to modules and tested against representative events before cutover. The design calls for explicit permissions, bounded execution and a Python-free production runtime.

## Local development

Install stable Rust with rustfmt and Clippy, just, and Docker Compose. Run `just` for available commands.

- `just setup` fetches locked dependencies.
- `just dev` starts PostgreSQL 17 and serves the API on localhost:8000.
- `just health` calls both probes. A fresh database returns 503 for readiness until the supported schema is migrated. The service never stamps a blank database as migrated.
- `just check` checks formatting, runs Clippy and executes the offline tests.
- `just test-db` runs the real PostgreSQL integration test after `just db-up`.
- `just db-down` stops local PostgreSQL and retains its volume.

For an existing PostgreSQL instance, set `DATABASE_URL` and use `just run`. Set `BIND_ADDR` to change the listen address, `PYLOROS_URL` for the probe recipe, or `PYLOROS_PG_PORT` to choose a different local database port.
