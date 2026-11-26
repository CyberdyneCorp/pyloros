# Pyloros

Pyloros is a Rust identity and authorization service under development. It serves health probes, issuer discovery and the authorization-code token exchange against PostgreSQL.

## Authorization

Role-based access control (RBAC) will let an application assign permissions to roles. For example, a reviewer might be allowed to approve submissions for one organization.

Relationship-based access control (ReBAC) will let an application grant access through relationships between people and resources. A reviewer might be allowed to open a particular submission because it belongs to a collection shared with their team. Applications can require both the reviewer role and access to that submission.

## Frontend

Pyloros will use the existing frontend source and build. For compatibility testing, run the same frontend artifact against both backends and switch the API destination through deployment routing. Browser workflows must pass with the existing client code.

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

## Discovery during migration

The three well-known endpoints serve OpenID Connect discovery, OAuth authorization-server metadata, and a public JWKS. They default to disabled. To publish metadata for an existing issuer, set `OIDC_ENABLED=true`, `OIDC_ISSUER`, and `JWT_PUBLIC_KEY_PATH` (an RSA public key in SPKI PEM format). An inline `JWT_PUBLIC_KEY` also works. The default key ID is the public JWK thumbprint; set `JWT_KEY_ID` when matching an existing signing key ID.

Set `OIDC_SCOPES` to the issuer's space-separated base scope catalog. Discovery adds active scopes from PostgreSQL at startup and every 30 seconds. Set `OAUTH_REGISTRY_REFRESH_SECONDS` to change the interval or use zero to serve only the configured base catalog. Failed reads retain the previous scope set. Set `OAUTH_DCR_ENABLED` and `OAUTH_DEVICE_GRANT_ENABLED` to match the issuer.

## Authorization code exchange

Set `JWT_ALGORITHM=RS256` and supply `JWT_PRIVATE_KEY_PATH` or an inline `JWT_PRIVATE_KEY` alongside the discovery configuration to activate `POST /api/v1/auth/oauth2/token`. The private key must match the published RSA public key. A discovery-only instance can continue using just the public key.

The [token endpoint](openspec/specs/oauth-token/spec.md) accepts the authorization-code grant with form or HTTP Basic credentials. Configure the access and ID lifetimes with `JWT_ACCESS_TOKEN_TTL_MINUTES` and `OIDC_ID_TOKEN_TTL_MINUTES` (both default to 15), and the refresh lifetime with `JWT_REFRESH_TOKEN_TTL_DAYS` (default 30). Set `OAUTH_PROTECTED_RESOURCES` to a JSON object mapping HTTPS resource URLs to scope lists or objects with scopes and an audience override. Configured audiences take precedence over active PostgreSQL registrations. The registry refresh interval also applies to resource audiences.

During coexistence, direct code exchanges to Pyloros for clients using PostgreSQL IAM that do not depend on login hooks. Keep refresh, client-credentials and device grants on the existing token handler. Moving the whole token path requires those grants and post-commit hook support.

## Specifications

The [health probes](openspec/specs/health/spec.md) and [issuer discovery](openspec/specs/issuer-discovery/spec.md) specifications describe the five foundation HTTP routes. The [HTTP response spec](openspec/specs/http-responses/spec.md) covers shared browser security headers. With the OpenSpec CLI installed, run `just spec-check` to validate the specifications.

## Comparing running services

Use `just compare <reference-url> <pyloros-url>` with two deployments configured for the same public issuer, key, scopes and feature flags. The Python 3 development tool checks status, JSON bodies and seven response headers on the five foundation routes. Pass `--oidc-disabled` for disabled discovery or `--not-ready` when both databases are unavailable or incompatible. A difference exits nonzero and identifies the affected field or header.

The [authorization-code storage contract](openspec/specs/authorization-code-storage/spec.md) defines how pending grants survive an issuer upgrade. The Rust exchange operation authenticates the registered client, checks its allowed grant, and verifies the S256 proof, redirect, resource, expiry and active user before claiming a grant. A committed replay refusal revokes the associated session and live refresh tokens.

The [grant session specification](openspec/specs/grant-sessions/spec.md) covers PostgreSQL session creation, RS256 refresh credentials and scoped ID tokens. The ID-token signer uses the calling client as its audience and includes consented profile and authorization claims. Session creation shares the authorization-code claim transaction and carries the original authentication time and methods into the new session.

The Rust access-token signer reads account, organization and entitlement claims from PostgreSQL. The caller supplies the effective resource registry, administrator email policy and any resolved role and permission claims. A resource-bound token uses the registered audience override or the resource URL. A grant without a resource uses the client’s configured audience when present. The grant-response operation creates the session and issues the consented credentials in the caller’s transaction, using one PostgreSQL IAM snapshot for both signers. Organization roles require an active membership, and permission mappings come from the calling client and eligible clients sharing the access-token audience. The code exchange commits tokens and their success audit record together. On refusal it preserves replay revocations, records a separate audit event, and returns the OAuth error even if that audit write fails.
