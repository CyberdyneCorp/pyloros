# Pyloros

Pyloros is a Rust identity and authorization service under development. It serves health probes, issuer discovery and the authorization-code token exchange against PostgreSQL.

## Authorization

Role-based access control (RBAC) will let an application assign permissions to roles. For example, a reviewer might be allowed to approve submissions for one organization.

Relationship-based access control (ReBAC) will let an application grant access through relationships between people and resources. A reviewer might be allowed to open a particular submission because it belongs to a collection shared with their team. Applications can require both the reviewer role and access to that submission.

## Frontend

Pyloros will use the existing frontend source and build. For compatibility testing, run the same frontend artifact against both backends and switch the API destination through deployment routing. Browser workflows must pass with the existing client code.

Set `CORS_ALLOWED_ORIGINS` to the frontend origins that may make credentialed requests, as a comma-separated list or JSON array. The default is `http://localhost:3001`. Active PostgreSQL web origins enabled for CORS also take effect on the registry refresh interval. Responses to allowed origins expose `X-CSRF-Token`.

For cookie-authenticated writes, the browser echoes the CSRF cookie in the `X-CSRF-Token` request header. The cookie name defaults to `csrf` and can be set with `CSRF_COOKIE_NAME`. When TLS terminates at a proxy, include the public frontend origin in the origin registry. The OAuth token endpoint authenticates grants separately and accepts its standard form submissions.

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

## Current user profile

The shared frontend checks its session with `GET /api/v1/users/me`. The endpoint supports the access cookie and bearer access tokens, including tokens from admin-registered OAuth clients. It reads the current account, primary organization, entitlements and roles from PostgreSQL. Applications can read the same sorted product and plan tokens directly with `GET /api/v1/users/me/entitlements`. Set `ENFORCE_TOKEN_REVOCATION=true` to check the token denylist, revoked sessions and account issuance cutoff.

Configure `JWT_ALGORITHM` and the same issuer and verification key as the issuing service. For HS256, provide `JWT_SECRET_KEY`. For RS256, provide `JWT_PUBLIC_KEY_PATH` or `JWT_PUBLIC_KEY`. A deployment without a verification key returns an authentication challenge.

## Login method discovery

The shared login page reads `GET /api/v1/auth/oauth/providers` and `GET /api/v1/auth/passkeys/capabilities`. The OAuth list reflects the configured Google and Microsoft client IDs and secrets. Passkey discovery reads `PASSKEYS_ENABLED`, `PASSKEYS_RP_ID` and `PASSKEYS_ORIGINS`. A client starts external sign-in at `GET /api/v1/auth/oauth/{provider}`. Pass `redirect=true` for an HTTP redirect or use the authorization URL in the JSON response. PostgreSQL stores the provider and return instructions for `OAUTH_STATE_TTL_SECONDS` (default 600). Fragment returns require an exact frontend URL from `OAUTH_CLIENT_REDIRECT_ALLOWLIST` or the active web-origin registry. CLI returns require `CLI_LOGIN_ENABLED`, a loopback port and an S256 code challenge. Either backend can complete the callback at `GET /api/v1/auth/oauth/callback/{provider}` using shared PostgreSQL state. The Rust callback issues browser sessions or returns a one-time CLI code. The CLI posts that code and its verifier to `POST /api/v1/auth/cli/exchange` to receive a federated session. Both backends can redeem codes issued by the other. Cookie-mode redirects set access, refresh, and CSRF cookies. With no frontend redirect or `OAUTH_POST_LOGIN_URL`, the JSON response includes both tokens and sets the access cookie. The unchanged login page has been exercised against both callback implementations using the development provider.

## Authorization code exchange

Set `JWT_ALGORITHM=RS256` and supply `JWT_PRIVATE_KEY_PATH` or an inline `JWT_PRIVATE_KEY` alongside the discovery configuration to activate `POST /api/v1/auth/oauth2/token`. The private key must match the published RSA public key. A discovery-only instance can continue using just the public key.

A browser or native client can start passkey sign-in through `POST /api/v1/auth/passkeys/login/options` without identifying the account. The response requests user verification and omits the credential list so the authenticator can offer discoverable credentials. Either backend can finish the assertion at `POST /api/v1/auth/passkeys/login/verify` using the shared PostgreSQL challenge and client binding. A valid assertion issues a session or starts a TOTP challenge. The client must retain its original origin and binding through MFA completion.

A signed-in client can request `POST /api/v1/auth/passkeys/reauth/options` to get the active credentials for its account and relying party. Either backend can complete the challenge at `POST /api/v1/auth/passkeys/reauth/verify`. An account with TOTP enabled must also supply an authenticator or recovery code. Success returns HTTP 204 and grants recent authentication to the originating session.

A recently authenticated user can start passkey enrollment with `POST /api/v1/auth/passkeys/register/options`. Either backend can finish through `POST /api/v1/auth/passkeys/register/verify` using the challenge stored in PostgreSQL. Rust records the verified credential and enrollment event together. Apple anonymous attestation requires a chain to the Apple WebAuthn root that is valid at registration time. Android Key enrollment checks the presented Google hardware root, certificate chain, and device-enforced signing authorization. The Pixel 8a registration path has been compared with the reference. Keep Android SafetyNet and Android Key certificates reporting the StrongBox security level on the existing verifier during coexistence. Both services must use the same ordered browser and native origin lists and relying party ID. `PASSKEYS_CHALLENGE_TTL_SECONDS` accepts 30–300 seconds and defaults to 300. Outside development, native clients require HTTPS through a proxy trusted by `FORWARDED_ALLOW_IPS`. Restrict that setting to your TLS-terminating proxies and configure them to overwrite the forwarded scheme.

With passkeys enabled, `GET /api/v1/auth/passkeys` lists the current account’s active credentials for `PASSKEYS_RP_ID` in creation order. A live first-party session is required. The response contains display metadata and uses `Cache-Control: no-store`. Set `PASSKEYS_RATE_LIMIT_PER_MIN` to a value from 1 to 100 (default 10) to limit requests per operation and source IP on each process. `PATCH /api/v1/auth/passkeys/{passkey_id}` accepts a JSON `name` of one to 64 characters, trims surrounding whitespace and returns the updated metadata. Cookie-authenticated writes require the CSRF header.

`DELETE /api/v1/auth/passkeys/{passkey_id}` requires recent authentication. A successful removal returns HTTP 204 and records a credential audit event. When the selected passkey is the account’s last one for its relying party, removal requires a verified password account, a linked Google or Microsoft identity, or a wallet identity. Concurrent removals are serialized per account.


With OIDC enabled, `GET` and form `POST /api/v1/auth/oauth2/logout` end the browser session and clear its cookies. A registered return URI can be selected with a client ID or signed ID-token hint. A refused redirect still ends the session. Set `PYLOROS_SIGNED_OUT_HTML_PATH` to the shared, private signed-out HTML artifact for the same page on both deployments. The default is a minimal confirmation page.

With OIDC enabled, `GET /api/v1/auth/oauth2/userinfo` accepts a bearer user access token and reads the current active account from PostgreSQL. It returns the subject plus available email, verification status, name and picture. This compatibility endpoint returns those fields for client-bound user tokens independently of their scopes. `ENFORCE_TOKEN_REVOCATION` applies to UserInfo.

With OIDC and RSA signing configured, `GET /api/v1/auth/oauth2/authorize` accepts first-party browser sessions and issues S256-bound codes for trusted clients or existing consent. `OIDC_CODE_TTL_SECONDS` defaults to 60. Set `OIDC_LOGIN_URL` (or `OAUTH_POST_LOGIN_URL`) for hosted sign-in. Login continuations use the public origin of `OIDC_ISSUER`. The consent form endpoint accepts signed tickets from the same issuer, binds them to the first-party session and rechecks the active client and callback. Approval merges the scopes and redirects back to the authorization request. Denial returns to the client. Set `PYLOROS_CONSENT_UI_PATH` to the deployment’s shared consent bundle to enable interactive approval. An absent bundle returns HTTP 503 when a new approval is required. A silent request needing consent redirects with `consent_required`.

The consent bundle is a local UTF-8 JSON object with a `template` string (MiniJinja HTML) and a `descriptions` object mapping scope names to display text. The template receives `client_name`, `client_id`, `self_registered`, `redirect_host`, `resource`, `scopes` (entries with `name` and `description`), `ticket` and `action`. Values are HTML-escaped. The form posts the ticket and a decision of `approve` or `deny` to `action`. Generate the deployment bundle from the same frontend revision used by the reference service and distribute it privately.


The [token endpoint](openspec/specs/oauth-token/spec.md) accepts the authorization-code grant with form or HTTP Basic credentials. Configure the access and ID lifetimes with `JWT_ACCESS_TOKEN_TTL_MINUTES` and `OIDC_ID_TOKEN_TTL_MINUTES` (both default to 15), and the refresh lifetime with `JWT_REFRESH_TOKEN_TTL_DAYS` (default 30). Set `OAUTH_PROTECTED_RESOURCES` to a JSON object mapping HTTPS resource URLs to scope lists or objects with scopes and an audience override. Configured audiences take precedence over active PostgreSQL registrations. The registry refresh interval also applies to resource audiences.

Pyloros validates environment-defined resource scopes at startup, including when OIDC is disabled. The default catalog includes `openid`, `profile`, `email`, `offline_access` and `roles`. Supply additional recognized names in the space-separated `PYLOROS_RESOURCE_SCOPE_CATALOG` deployment setting. For migration, supply the reference deployment’s complete application scope catalog. This setting controls configuration validation independently of discovery and client grants.


During coexistence, direct code exchanges to Pyloros for clients using PostgreSQL IAM that do not depend on login hooks. Keep refresh, client-credentials and device grants on the existing token handler. Moving the whole token path requires those grants and post-commit hook support.

## Specifications

The [health probes](openspec/specs/health/spec.md) and [issuer discovery](openspec/specs/issuer-discovery/spec.md) specifications describe the five foundation HTTP routes. The [HTTP response spec](openspec/specs/http-responses/spec.md) covers shared browser security headers. With the OpenSpec CLI installed, run `just spec-check` to validate the specifications.

## Comparing running services

Use `just compare <reference-url> <pyloros-url>` with two deployments configured for the same public issuer, key, scopes and feature flags. The Python 3 development tool checks status, JSON bodies and seven response headers on the five foundation routes. Pass `--oidc-disabled` for disabled discovery or `--not-ready` when both databases are unavailable or incompatible. A difference exits nonzero and identifies the affected field or header.

The [authorization-code storage contract](openspec/specs/authorization-code-storage/spec.md) defines how pending grants survive an issuer upgrade. The Rust exchange operation authenticates the registered client, checks its allowed grant, and verifies the S256 proof, redirect, resource, expiry and active user before claiming a grant. A committed replay refusal revokes the associated session and live refresh tokens.

The [grant session specification](openspec/specs/grant-sessions/spec.md) covers PostgreSQL session creation, RS256 refresh credentials and scoped ID tokens. The ID-token signer uses the calling client as its audience and includes consented profile and authorization claims. Session creation shares the authorization-code claim transaction and carries the original authentication time and methods into the new session.

The Rust access-token signer reads account, organization and entitlement claims from PostgreSQL. The caller supplies the effective resource registry, administrator email policy and any resolved role and permission claims. A resource-bound token uses the registered audience override or the resource URL. A grant without a resource uses the client’s configured audience when present. The grant-response operation creates the session and issues the consented credentials in the caller’s transaction, using one PostgreSQL IAM snapshot for both signers. Organization roles require an active membership, and permission mappings come from the calling client and eligible clients sharing the access-token audience. The code exchange commits tokens and their success audit record together. On refusal it preserves replay revocations, records a separate audit event, and returns the OAuth error even if that audit write fails.

First-party sessions can edit their phone with `PATCH /api/v1/users/me`. Send a JSON object with a `phone` string. An empty string removes the phone. A supplied string clears phone verification, including when resubmitting the current number. Omitting the field or sending null preserves verification. Phone changes are audited in the same PostgreSQL transaction.

The email-confirmation transport supports `EMAIL_PROVIDER=mock` (the default) and `EMAIL_PROVIDER=smtp`. SMTP uses `SMTP_HOST`, `SMTP_PORT` (default 587), optional `SMTP_USERNAME` and `SMTP_PASSWORD`, and `EMAIL_FROM`. Port 465 uses implicit TLS. Other ports require STARTTLS. Set `ACCOUNT_LINKS_BASE_URL` to the browser application's public base, including its mount path. The fallback is the origin of `OIDC_LOGIN_URL` or `OAUTH_POST_LOGIN_URL`.

For PostgreSQL IAM deployments, `POST /api/v1/auth/login` supports password sign-in and starts TOTP or email confirmation when required. Successful single-factor login writes the session and audit event together and returns the token pair and browser cookies. During coexistence, send login traffic to the legacy service when active login hooks need its dispatcher. Pyloros returns 503 before creating a login session in that configuration.

The email recipient can inspect, confirm or deny a pending sign-in on Pyloros through the shared frontend. The three recipient endpoints share a per-source quota. The initiating browser polls `POST /api/v1/auth/magic-link/status` with its MFA credential. A pending challenge returns 202. Once approved, a single poll consumes it and returns the token pair and session cookies.

For password-bound TOTP challenges, the shared frontend can submit the authenticator or recovery code to `POST /api/v1/auth/mfa/verify`. Configure `MASTER_KEY` with the same value used to encrypt the existing enrollments. A successful check consumes the factor in the transaction that records the session and MFA audit event.

Services authenticate at `POST /api/v1/auth/oauth2/token` with `grant_type=client_credentials` using HTTP Basic or form credentials. The grant uses the client's configured token lifetime, scope and audience policy, and supports secret rotation. It remains available when OIDC browser sign-in is disabled.

A resource server can authenticate with a service bearer and post a token to `/api/v1/auth/introspect`. Introspection checks the submitted token’s current revocation state and resolves user membership, entitlements, roles and permissions from PostgreSQL. A service can also read its live registration at `GET /api/v1/clients/me`.

OAuth clients can submit a token to `POST /api/v1/auth/oauth2/revoke` using HTTP Basic or form credentials. Revoking a client-owned access or service token records its identifier. Revoking a client-owned refresh token ends its session and refresh family. Both backends enforce the shared PostgreSQL records when access-token revocation enforcement is enabled.

Browser sessions rotate at `POST /api/v1/auth/refresh` using a refresh cookie or JSON token. Rotation preserves the login’s authentication time and methods and reloads account claims. Set `REFRESH_REUSE_GRACE_SECONDS` (default 10, range 0–60) to tolerate another tab presenting a recently rotated token. Reuse outside that interval revokes the session and its remaining refresh tokens.

The shared frontend signs out through `POST /api/v1/auth/logout`. A valid refresh token revokes its session family. A presented access token is denylisted until expiry. Configure `ENFORCE_TOKEN_REVOCATION=true` for immediate enforcement on protected reads.

From Preferences, a first-party user can sign out on all devices through `POST /api/v1/auth/logout-all`. The operation revokes that account’s live sessions and advances its access-token cutoff. Cookie-authenticated calls require the CSRF header.

The Preferences screen reads `GET /api/v1/auth/mfa/status` with a first-party access token. The response reports the account’s authenticator enrollment and remaining unused recovery codes.

Preferences starts authenticator enrollment at `POST /api/v1/auth/mfa/totp/setup`. Scan the QR image or enter its Base32 secret, then confirm a current code at `POST /api/v1/auth/mfa/totp/enable`. Store the ten returned recovery codes when they are shown. `MFA_ISSUER` sets the account label in the authenticator app.

From the same Preferences screen, an enrolled account can replace its recovery codes or disable the authenticator. Both operations require a fresh authenticator code. Password accounts must also supply their password. Passwordless accounts need recent authentication on the calling session. Replacing codes invalidates the previous set immediately.

Preferences submits the current and replacement password to `POST /api/v1/auth/password/change`. A successful change returns 204, revokes every active refresh session for the account and advances its access-token cutoff. Deployments that enforce token revocation reject previously issued access tokens. The replacement hash uses the configured `PASSWORD_SCHEME`.

The existing forgot-password form submits to `POST /api/v1/auth/password/reset-request`. Set `RATELIMIT_RESET_PER_HOUR` to configure the per-source quota (default 5). With SMTP and an account URL configured, the recipient gets a link to the existing reset form. The link expires after one hour. The form submits to `POST /api/v1/auth/password/reset-confirm`. Redemption verifies the email address, applies eligible domain-based organization membership, replaces the password and revokes existing sessions.

Submit the email verification code to `POST /api/v1/auth/verify-email` as the JSON string field `token`. Success returns an empty 204. Verification consumes the code and applies the verified email domain’s organization membership rules.

`POST /api/v1/auth/register` creates an unverified password account with a managed Ethereum wallet, emails its verification code, and returns the account ID, normalized email, public key and address. Configure `MASTER_KEY` identically across writers. `RATELIMIT_REGISTER_PER_MIN` defaults to 10 per source. With webhooks enabled, matching subscriptions receive transactional outbox rows for the existing delivery worker. During coexistence, route registration to the legacy backend when an active registration hook requires its dispatcher. Pyloros returns 503 before creating the account in that configuration.
