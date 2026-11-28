# Pyloros

Pyloros is a Rust identity and authorization service under development. It provides OAuth and OpenID Connect, account and session management, and application authorization backed by PostgreSQL.

## Authorization

Role-based access control (RBAC) lets an application assign permissions to roles and grant roles to users globally or within an organization. A service client with `roles:manage` can list its roles at `GET /api/v1/clients/me/roles` and inspect a role’s permissions at `GET /api/v1/clients/me/roles/{role_key}/permissions`. See the [role mapping handoff procedure](docs/role-mapping-handoff.md) when switching writers on a shared database.

Relationship-based access control (ReBAC) lets an application check access to a specific object through relationships between people and resources. A reviewer might be allowed to open a particular submission because it belongs to a collection shared with their team. Applications can require both the reviewer role and access to that submission.

Application object IDs belong to the calling client. Remove assignments involving a deleted application object before reusing its ID, including assignments where it appears as the subject. [OpenAPI contract and request examples](openapi/rebac.yaml) · [Typed operator CLI commands](integrations/operator-cli/README.md)

Run `just check-rebac-contract` to validate the OpenAPI description and its JSON examples, including the inherited permission and revocation responses.

The first ReBAC migration adds client-owned graph storage to an existing PostgreSQL database. It supports relationships to accounts and between application objects. Deleting an account removes its direct relationships. If an administrator provisions the same email address again, the replacement account has a new UUID. Grant membership to that UUID to restore its object access. Deleting a client removes its graph. [PostgreSQL migration](migrations/005_relationship_graphs.sql)

An operator can register the custom OAuth scope `rebac:manage` and grant it to a confidential service client. Use the Pyloros client-credentials token endpoint to obtain a token for this scope. The token identifies the client registration by UUID so its authority expires if that registration is replaced. Call `PUT /api/v1/clients/me/rebac/model` with the bearer token and a JSON model. For example, this model lets an account read a collection through direct membership or a parent collection.

```json
{
  "types": {
    "collection": {
      "relations": {"member": ["user"], "parent": ["collection"]},
      "permissions": {"read": [{"relation": "member"}, {"via": "parent", "permission": "read"}]}
    }
  }
}
```

Models accept up to 65,536 permission references in total, counting each direct proof once and each inherited proof once per declared destination type. An accepted model returns HTTP 204. A change that would invalidate an existing assignment returns HTTP 409. Use the same service token with `PUT /api/v1/clients/me/rebac/relationships` to grant a relationship. Use `DELETE` with the same JSON body to revoke it. For the collection model above, this makes one collection a child of another.

```json
{"object":{"type":"collection","id":"drafts"},"relation":"parent","subject":{"type":"collection","id":"library"}}
```

For direct membership, use relation `member` and a subject of type `user` with the account UUID as its ID. Each successful write returns HTTP 204. Retries preserve the assignment state and produce one audit record per actual change. To evaluate access, grant the calling service the separate `rebac:check` scope and send its token to `POST /api/v1/clients/me/rebac/check` with a JSON body such as:

```json
{"user_id":"00000000-0000-0000-0000-000000000001","object":{"type":"collection","id":"drafts"},"permission":"read"}
```

A completed check returns HTTP 200 and `{"allowed":true}` or `{"allowed":false}`. Each check reads a fresh snapshot on the PostgreSQL primary. It follows up to 16 relationship hops and spends up to 1,024 units across permission rules and traversed edges. A check that cannot establish an answer within these limits, or cannot read its graph, returns HTTP 503. Applications should grant access only on an explicit allow. Apply any required role or organization checks alongside this decision.

For a database failover rehearsal, give two service clients access to identically named objects in their own graphs. Revoke one membership and confirm that both API replicas deny direct and inherited access for that client while allowing the other. After promotion, repeat the checks with the same service tokens before sending any relationship writes. Replaying the revoke should leave one deletion audit. A local PostgreSQL 17 rehearsal with synchronous `remote_apply` replication passed these checks. During the writer outage both replicas returned HTTP 503 for the previously allowed client. Repeat the rehearsal with the replication and routing settings used in deployment.

## Frontend

Run the existing frontend build at one origin and switch its API upstream through deployment routing. Record the frontend source revision and build digest once. During cutover and rollback, fetch the browser assets through the deployment URL and compare their bytes to that build. For assets with an ETag, send the previous ETag in `If-None-Match` and verify that the server returns 304. This checks that browsers can reuse the files they cached before the switch.

Record the original digest with `just check-frontend-build PATH_TO_BUILD`. Before starting the frontend from a relocated package, run `just check-frontend-build PATH_TO_BUILD EXPECTED_SHA256` against the digest recorded for the reviewed build. The check covers the server bundle and client assets. It hashes each relative path, a zero byte and the binary SHA-256 of the corresponding file in sorted path order. Record the lockfile digest, Node version and deployment platform separately for runtime dependencies.

Load the console routes against each upstream with the same authenticated account. Compare the final URLs, page headings, API methods, paths and response statuses, and check for uncaught browser errors. Exercise writes and their stored effects separately.

Set `CORS_ALLOWED_ORIGINS` to the frontend origins that may make credentialed requests, as a comma-separated list or JSON array. The default is `http://localhost:3001`. Active PostgreSQL web origins enabled for CORS also take effect on the registry refresh interval. Responses to allowed origins expose `X-CSRF-Token`.

For cookie-authenticated writes, the browser echoes the CSRF cookie in the `X-CSRF-Token` request header. The cookie name defaults to `csrf` and can be set with `CSRF_COOKIE_NAME`. When TLS terminates at a proxy, include the public frontend origin in the origin registry. The OAuth token endpoint authenticates grants separately and accepts its standard form submissions.

## Compatibility goals

The design starts from the experience of application developers, users and operators. Priorities include interoperable sign-in and token handling, account and session management, administrative tools, auditability, and reliable integration events. Compatibility will be assessed through observable behavior and migration tests as the service develops.

## Extension hooks

With hooks enabled, Pyloros starts a CONNECT proxy on `HOOKS_PROXY_HOST` and `HOOKS_PROXY_PORT` (default `127.0.0.1:8787`). Set `HOOKS_EGRESS_ALLOWLIST` to a comma-separated list or JSON array of allowed domains. The default is empty. The proxy checks each resolved address before connecting and permits ports 80 and 443. Readiness includes `hook_egress_proxy` while hooks are enabled. If the listener cannot bind, this field is false and database readiness is evaluated independently.

The proposed hook runtime is WebAssembly, hosted by Rust. Existing scripts would be ported to modules and tested against representative events before cutover. The design calls for explicit permissions, bounded execution and a Python-free production runtime.

Administrators can inspect saved hook definitions at `GET /api/v1/admin/hooks` and `GET /api/v1/admin/hooks/{hook_id}`. The definitions include stored source, active status, timeout, network access and the personal-data opt-in. Execution history at `GET /api/v1/admin/hooks/{hook_id}/executions` supports `limit` (1–100, default 50) and `offset` (default 0). It returns the total and a newest-first page of outcomes. All three reads work with the executor disabled. Administrators can remove a hook with `DELETE /api/v1/admin/hooks/{hook_id}`. A successful deletion removes its execution history and records the operator action in the audit log.

## Stripe Checkout

Set `BILLING_ENABLED=true` and configure `STRIPE_API_KEY` on the server to enable `POST /api/v1/billing/stripe/checkout`. The caller supplies `price_id`, `product_key`, `success_url`, and `cancel_url`. The optional `mode` accepts `subscription` (default) or `payment`, and `plan` identifies the product tier.

The response contains the hosted session's `id` and `url`. The service identifies the signed-in user to Stripe, reuses a mapped customer when available, and sends one line item. Each new checkout request gets a new provider idempotency key. Retries of that provider request reuse its key. Fulfillment begins when Stripe sends a signed event to `POST /api/v1/webhooks/stripe`. Set `STRIPE_WEBHOOK_SECRET` to the endpoint signing secret. The handler verifies the original bytes, updates entitlements and records the outcome in one PostgreSQL transaction. Redelivery of a processed event is acknowledged. An event deferred for missing business data can be reapplied after that data becomes available.

Pyloros intentionally fulfills correctly signed events that the previous provider adapter could reject with HTTP 500 during decoding. When hook processing is enabled, an active entitlement hook without a selected version or enabled store dispatcher keeps the billing notification retryable with HTTP 503.

A subscription update can arrive before checkout maps the customer. Redelivery after checkout applies the new plan and its expiry. An `invoice.created` event is informational and returns `handled: false`. A refund for a separate one-time payment revokes only the grants tied to that payment reference.

## App Store purchases

Set `BILLING_ENABLED=true`, `APPLE_BUNDLE_ID` and `APPLE_ROOT_CA_DIR` on the server. Install trusted Apple roots as DER certificate files in that directory. Set `APPLE_ENVIRONMENT` to `Sandbox` or `Production` (default), and supply `APPLE_APP_APPLE_ID` for production. The server needs network access to the OCSP responders listed in the trusted certificate chain.

Signed-in customers submit the StoreKit JWS in `signed_transaction` to `POST /api/v1/billing/apple/validate`. Successful claims return the mapped entitlement token and expiry. An original transaction can belong to one account. Pyloros rejects receipts that show revocation or expiry and checks a replay against the stored entitlement. An unavailable certificate status service returns HTTP 503 so the app can retry.

Configure App Store Server Notifications V2 to send `signedPayload` to `POST /api/v1/webhooks/apple`. Pyloros verifies the envelope and nested StoreKit records before changing access. Renewals extend the mapped grant, including a verified billing-retry grace period. Expiry and refund events withdraw the corresponding App Store grant. Processed notification IDs are acknowledged on replay. An unresolved purchase or product is recorded as deferred and can be resubmitted once it is mapped.

## Google Play purchases

Enable billing with `BILLING_ENABLED=true`, set `GOOGLE_PACKAGE_NAME` to the Android application ID, and supply `GOOGLE_SERVICE_ACCOUNT_JSON` as a server-side secret with Android Publisher access. Signed-in users submit `purchase_token` and `product_id` to `POST /api/v1/billing/google/validate`. Pyloros checks the purchased line item and expiry with Google before granting the mapped product. A purchase can belong to one account. An active entitlement hook requires the dispatcher before the grant can commit.

Before routing Play claims, check the character limits on both columns that store the purchase token. The stock migration schema allows 512 characters in `google_purchases.purchase_token` and 128 in `entitlements.external_ref`. In local tests with a synthetic store, 128-character tokens committed on both backends. At 129, 511 and 512 characters both returned HTTP 500 and rolled back ownership and access. At 513 characters both returned HTTP 422. ASCII and multibyte tokens gave the same results. With a 512-character entitlement reference in a disposable database, both backends committed the previously failing claims.

```sql
SELECT table_schema, table_name, column_name, data_type, character_maximum_length
FROM information_schema.columns
WHERE (table_name, column_name) IN (
    ('google_purchases', 'purchase_token'),
    ('entitlements', 'external_ref')
)
ORDER BY table_schema, table_name;
```

If a deployment elects to widen the entitlement reference, drain requests from the reference replicas and close their database pools before applying the change. A reference login with a prepared entitlement query returned HTTP 500 after the column changed underneath its pool. Set a transaction-local lock timeout on the schema change. In the PostgreSQL 17 rehearsal, a held reader caused the change to time out and the column stayed at 128 characters. The change committed after the reader finished.

With the reference offline, the already-running Rust process served a fresh login and read the existing entitlement using a reference-issued token after the change. After restarting the reference, each backend rotated a refresh token issued by the other before the change. Exercise these checks with the deployment's signing settings and actual connection pools before routing login traffic back.

For subscription updates, configure an authenticated Google Pub/Sub push subscription to `POST /api/v1/webhooks/google`. Set `GOOGLE_PUBSUB_AUDIENCE` to its exact audience and `GOOGLE_PUBSUB_SERVICE_ACCOUNT_EMAIL` to its push identity. Pyloros verifies the sender and application, then checks current subscription state with Play. Canceled subscriptions retain access until the confirmed expiry. Processed message IDs are acknowledged on replay. An unknown purchase or product is recorded as deferred and can be resubmitted after the mapping exists. A temporary provider failure returns HTTP 503 so Pub/Sub can retry.

## Outbound webhooks

By default, each service replica runs a PostgreSQL outbox worker when webhooks are enabled. Set `PYLOROS_WEBHOOK_WORKER_ENABLED=false` on a canary to leave delivery to the current owner. Keep `WEBHOOKS_ENABLED=true` so the canary continues to enqueue events. To transfer ownership, stop the old worker and start a worker-enabled replica against the same PostgreSQL database. Replicas lease queued deliveries before sending them. The worker signs the stored body with the subscription key and includes both signatures during key rotation. Configure the same `MASTER_KEY` on all replicas.

A receiver can process a webhook just before the worker loses its connection or stops. If the worker cannot record the acknowledgement, another worker can send the same event after its lease expires. Both requests carry the same `webhook-id` and body. Verify each signature, then record the message ID together with the business change in one transaction. If the ID was already processed, return a successful response. Delivery history counts attempts that the worker recorded, so a receiver can see more requests than the history shows.

By default each replica claims up to 50 deliveries per batch, runs eight sends concurrently, allows ten seconds per request and polls every two seconds when the batch is smaller than the limit. Set `WEBHOOKS_BATCH_SIZE`, `WEBHOOKS_MAX_CONCURRENCY`, `WEBHOOKS_REQUEST_TIMEOUT_SECONDS` and `WEBHOOKS_POLL_INTERVAL_SECONDS` to tune these values. The worker pins HTTPS connections to checked public addresses. For local receiver testing, `WEBHOOKS_ALLOW_INSECURE_HTTP=true` permits HTTP and local addresses in development.

## Capacity measurements

[Mixed login, refresh and introspection results on PostgreSQL](docs/capacity.md) cover one and two API processes under scheduled traffic.

## Local development

Install stable Rust with rustfmt and Clippy, OpenSSL development headers and libraries, just, and Docker Compose. Run `just` for available commands.

- `just setup` fetches locked dependencies.
- `just dev` starts PostgreSQL 17 and serves the API on localhost:8000.
- `just health` calls both probes. A fresh database returns 503 for readiness until the supported schema is migrated. The service never stamps a blank database as migrated. A readiness request can wait up to 30 seconds for one of the pool’s 15 connections. PostgreSQL statement and lock timeouts govern the migration query. A timed-out connection attempt can trigger one diagnostic connection at a time to identify the failure.
- `just check` checks formatting, runs Clippy and executes the offline tests.
- `just test-db` runs the real PostgreSQL integration test after `just db-up`.
- `just db-commit-checks` inventories deferrable table constraints and triggers before a database handoff. Set `DATABASE_URL` to a read-only login for the target database. The JSON includes initially immediate checks and disabled triggers. An empty array means the database catalogs list no deferrable checks on application tables. Connection or storage failures can still interrupt commit.
- `just db-down` stops local PostgreSQL and retains its volume.

For an existing PostgreSQL instance, set `DATABASE_URL` and use `just run`. Set `BIND_ADDR` to change the listen address, `PYLOROS_URL` for the probe recipe, or `PYLOROS_PG_PORT` to choose a different local database port.

## Discovery during migration

The three well-known endpoints serve OpenID Connect discovery, OAuth authorization-server metadata, and a public JWKS. They accept GET and default to disabled. A disabled endpoint returns the standard 404 problem document. HS256 is the default signing algorithm. For RSA discovery, set `OIDC_ENABLED=true`, `JWT_ALGORITHM=RS256`, and `JWT_PUBLIC_KEY_PATH` (an RSA public key or a PEM certificate containing it). An inline `JWT_PUBLIC_KEY` also works. Set `OIDC_ISSUER` for a fixed public base. When omitted, discovery, ID tokens and device links use the request origin. The service honors forwarded HTTPS from peers in `FORWARDED_ALLOW_IPS`. Session tokens retain the exact configured `OIDC_ISSUER`, falling back to `JWT_ISSUER`. With a configured issuer and `JWT_ALGORITHM=HS256`, discovery publishes an empty JWKS. The default key ID is the public JWK thumbprint; set `JWT_KEY_ID` when matching an existing signing key ID.

To ship deployment-specific defaults, set `PYLOROS_BUILD_SCOPE_CATALOG` to the space-separated built-in scope names when running `cargo build --release --locked`. Run the built executable with `--print-build-scope-catalog` to verify its embedded names before deployment. It prints a JSON array for an explicit catalog and JSON null for a portable build. The executable carries those names into discovery, the administrative registry, and protected-resource configuration. Use the issuer’s built-in catalog as the build input. PostgreSQL manages the lifecycle of database-defined scopes. At runtime, `OIDC_SCOPES` overrides the discovery base, including when explicitly empty. A portable build uses `openid profile email offline_access` as its discovery base. Discovery adds active scopes from PostgreSQL at startup and every 30 seconds. Set `OAUTH_REGISTRY_REFRESH_SECONDS` to change the interval or use zero to disable periodic reads while still publishing local administrative writes. Failed reads retain the previous scope set. Set `OAUTH_DCR_ENABLED` and `OAUTH_DEVICE_GRANT_ENABLED` to match the issuer.

## Current user profile

The shared frontend checks its session with `GET /api/v1/users/me`. The endpoint supports the access cookie and bearer access tokens, including tokens from admin-registered OAuth clients. It reads the current account, primary organization, entitlements and roles from PostgreSQL. Applications can read the same sorted product and plan tokens directly with `GET /api/v1/users/me/entitlements`. Set `ENFORCE_TOKEN_REVOCATION=true` to check the token denylist, revoked sessions and account issuance cutoff.

Configure `JWT_ALGORITHM` and the same issuer and verification key as the issuing service. For HS256, provide `JWT_SECRET_KEY`. For RS256, provide `JWT_PUBLIC_KEY_PATH` or `JWT_PUBLIC_KEY`. A deployment without a verification key returns an authentication challenge.

## Login method discovery

The shared login page reads `GET /api/v1/auth/oauth/providers` and `GET /api/v1/auth/passkeys/capabilities`. The OAuth list reflects the configured Google and Microsoft client IDs and secrets. Passkey discovery reads `PASSKEYS_ENABLED`, `PASSKEYS_RP_ID` and `PASSKEYS_ORIGINS`. A client starts external sign-in at `GET /api/v1/auth/oauth/{provider}`. Pass `redirect=true` for an HTTP redirect or use the authorization URL in the JSON response. PostgreSQL stores the provider and return instructions for `OAUTH_STATE_TTL_SECONDS` (default 600). Fragment returns require an exact frontend URL from `OAUTH_CLIENT_REDIRECT_ALLOWLIST` or the active web-origin registry. CLI returns require `CLI_LOGIN_ENABLED`, a loopback port and an S256 code challenge. Either backend can complete the callback at `GET /api/v1/auth/oauth/callback/{provider}` using shared PostgreSQL state. The Rust callback issues browser sessions or returns a one-time CLI code. The CLI posts that code and its verifier to `POST /api/v1/auth/cli/exchange` to receive a federated session. Both backends can redeem codes issued by the other. Cookie-mode redirects set access, refresh, and CSRF cookies. With no frontend redirect or `OAUTH_POST_LOGIN_URL`, the JSON response includes both tokens and sets the access cookie. The unchanged login page has been exercised against both callback implementations using the development provider.

## Authorization code exchange

For RS256 token issuance, set `JWT_ALGORITHM=RS256` and supply `JWT_PRIVATE_KEY_PATH` or an inline `JWT_PRIVATE_KEY` alongside the discovery configuration to activate `POST /api/v1/auth/oauth2/token`. The private key must match the published RSA public key. A discovery-only instance can use just the public key. For HS256 OAuth grants, configure `JWT_SECRET_KEY`. An authorization code requesting `openid` is consumed and returns OAuth `server_error` because ID tokens require RS256.

A browser or native client can start passkey sign-in through `POST /api/v1/auth/passkeys/login/options` without identifying the account. The response requests user verification and omits the credential list so the authenticator can offer discoverable credentials. Either backend can finish the assertion at `POST /api/v1/auth/passkeys/login/verify` using the shared PostgreSQL challenge and client binding. A valid assertion issues a session or starts a TOTP challenge. The client must retain its original origin and binding through MFA completion.

A signed-in client can request `POST /api/v1/auth/passkeys/reauth/options` to get the active credentials for its account and relying party. Either backend can complete the challenge at `POST /api/v1/auth/passkeys/reauth/verify`. An account with TOTP enabled must also supply an authenticator or recovery code. Success returns HTTP 204 and grants recent authentication to the originating session.

A recently authenticated user can start passkey enrollment with `POST /api/v1/auth/passkeys/register/options`. Either backend can finish through `POST /api/v1/auth/passkeys/register/verify` using the challenge stored in PostgreSQL. Rust records the verified credential and enrollment event together. Apple anonymous attestation requires a chain to the Apple WebAuthn root that is valid at registration time. Android Key enrollment checks the presented Google hardware root, certificate chain, and device-enforced signing authorization. The Pixel 8a registration path has been compared with the reference. Keep Android SafetyNet and Android Key certificates reporting the StrongBox security level on the existing verifier during coexistence. Both services must use the same ordered browser and native origin lists and relying party ID. `PASSKEYS_CHALLENGE_TTL_SECONDS` accepts 30–300 seconds and defaults to 300. Outside development, native clients require HTTPS through a proxy trusted by `FORWARDED_ALLOW_IPS`. Restrict that setting to your TLS-terminating proxies and configure them to overwrite the forwarded scheme.

For hardware enrollment, Pyloros accepted the public packed YubiKey/Firefox capture with user verification. Four TPM captures, including Surface Pro 4, Dell XPS 13 and Lenovo Carbon X1, used an RSA/SHA-1 attestation signature (COSE RS1). Pyloros rejected all four, including the capture with an ES256 credential key. This affects enrollment with those attestation statements. Existing passkey sign-in uses a separate assertion verifier. [Packed captures](https://github.com/duo-labs/py_webauthn/blob/0c8f53b08fdac667587e22d1792f59afa9e8455d/tests/test_verify_registration_response_packed.py) · [TPM captures](https://github.com/duo-labs/py_webauthn/blob/0c8f53b08fdac667587e22d1792f59afa9e8455d/tests/test_verify_registration_response_tpm.py)

Public YubiKey Bio 5.5.4 and 5.5.5 ES256 recordings completed enrollment on either backend and sign-in on the other. Both directions produced usable sessions and advanced the stored counters from 1 to 4 and from 3 to 7, respectively. The 5.5.6 recording used an EdDSA credential, outside the advertised ES256 and RS256 algorithms, and both backends returned 401 at enrollment. The offline test used the recorded challenges and account handles in disposable PostgreSQL databases. [Yubico recordings](https://github.com/Yubico/java-webauthn-server/blob/3a7edfb2609696808e8daad2508115bd43d88d3f/webauthn-server-core/src/test/scala/com/yubico/webauthn/test/RealExamples.scala#L536)

With passkeys enabled, `GET /api/v1/auth/passkeys` lists the current account’s active credentials for `PASSKEYS_RP_ID` in creation order. A live first-party session is required. The response contains display metadata and uses `Cache-Control: no-store`. Set `PASSKEYS_RATE_LIMIT_PER_MIN` to a value from 1 to 100 (default 10) to limit requests per operation and source IP on each process. `PATCH /api/v1/auth/passkeys/{passkey_id}` accepts a JSON `name` of one to 64 characters, trims surrounding whitespace and returns the updated metadata. Cookie-authenticated writes require the CSRF header.

`DELETE /api/v1/auth/passkeys/{passkey_id}` requires recent authentication. A successful removal returns HTTP 204 and records a credential audit event. When the selected passkey is the account’s last one for its relying party, removal requires a verified password account, a linked Google or Microsoft identity, or a wallet identity. Concurrent removals are serialized per account.


For migration deployments, install [the migration launcher](scripts/pyloros-migration) alongside the release binary and hook worker. Place the deployment’s existing assets in that directory as `signed-out.html`, `consent-ui.json`, `device-ui.json`, `erasure-report.json`, `migration-openapi.json` and `migration-openapi.csp`. Start `./pyloros-migration` to use those assets from any working directory. Explicit asset environment settings take precedence.

With OIDC enabled, `GET` and form `POST /api/v1/auth/oauth2/logout` end the browser session and clear its cookies. A registered return URI can be selected with a client ID or signed ID-token hint. A refused redirect still ends the session. Set `PYLOROS_SIGNED_OUT_HTML_PATH` to the shared, private signed-out HTML artifact for the same page on both deployments. The default is a minimal confirmation page.

With OIDC enabled, `GET /api/v1/auth/oauth2/userinfo` accepts a bearer user access token and reads the current active account from PostgreSQL. It returns the subject plus available email, verification status, name and picture. This compatibility endpoint returns those fields for client-bound user tokens independently of their scopes. `ENFORCE_TOKEN_REVOCATION` applies to UserInfo.

With OIDC and session signing configured, `GET /api/v1/auth/oauth2/authorize` accepts first-party browser sessions and issues S256-bound codes for trusted clients or existing consent. `OIDC_CODE_TTL_SECONDS` defaults to 60. Set `OIDC_LOGIN_URL` (or `OAUTH_POST_LOGIN_URL`) for hosted sign-in. Login continuations return to the browser’s original host and port. When ingress terminates TLS, preserve the browser host and configure the proxy as a trusted peer so the continuation retains HTTPS. The consent form endpoint accepts signed tickets from the same issuer, binds them to the first-party session and rechecks the active client and callback. Approval merges the scopes and redirects back to the authorization request. Denial returns to the client. Set `PYLOROS_CONSENT_UI_PATH` to the deployment’s shared consent bundle to enable interactive approval. An absent bundle returns HTTP 503 when a new approval is required. A silent request needing consent redirects with `consent_required`.

The consent page uses the process’s published registry for managed scope descriptions. Chromium enforces the page’s `form-action 'self'` policy across redirects following a decision. In the tested native loopback flow, a callback on another origin received neither the approval code nor the denial. Approval had already saved the consent grant.

The consent bundle is a local UTF-8 JSON object with a `template` string (MiniJinja HTML) and a `descriptions` object mapping scope names to display text. The template receives `client_name`, `client_id`, `self_registered`, `redirect_host`, `resource`, `scopes` (entries with `name` and `description`), `ticket` and `action`. Values are HTML-escaped. The form posts the ticket and a decision of `approve` or `deny` to `action`. Generate the deployment bundle from the same frontend revision used by the reference service and distribute it privately.


Administrators can inspect OAuth applications with `GET /api/v1/admin/oauth/clients` and `GET /api/v1/admin/oauth/clients/{client_id}`. The collection accepts `page`, `page_size` (up to 200), and `active_only`. These reads accept a first-party session from the admin console or CLI and check current admin access on each request. Set `ADMIN_API_ENABLED=false` to disable administrative access. Operators can deactivate an application with `DELETE /api/v1/admin/oauth/clients/{client_id}`. The client stays visible in the inventory, and its deactivation and operator audit entry commit together.

The dashboard reads overview, activity, registration and sign-in method reports from `/api/v1/admin/analytics`. When migrating, set `PYLOROS_REGISTRATION_TIME_ZONE` to the value returned by `SHOW TimeZone` on a reference application connection. For a migration package, you can also save that single value in a file named `registration-time-zone` alongside the launcher. An explicit environment setting takes precedence. This preserves registration dates around midnight. The default uses the Pyloros database connection’s time zone.

Administrators can list OAuth scopes with `GET /api/v1/admin/oauth/scopes` and inspect one with `GET /api/v1/admin/oauth/scopes/{name}`. The list sorts by scope name and includes inactive entries unless `active_only=true`. Both endpoints read managed entries directly from PostgreSQL. To match a migrating deployment’s built-in catalog, supply its additional names in `PYLOROS_RESOURCE_SCOPE_CATALOG` and its descriptions in the shared consent bundle.

Administrators can list protected resources with `GET /api/v1/admin/oauth/protected-resources`. The list includes deployment-configured resources and all managed entries, ordered by resource URI. Use `GET /api/v1/admin/oauth/protected-resources/{entry_id}` to inspect a managed entry by UUID, including a deactivated entry. Administrators can deactivate it with `DELETE /api/v1/admin/oauth/protected-resources/{entry_id}`. Once its audit entry and deactivation commit, the writer rejects refreshes bound to the removed resource and updates the scopes available for dynamic client registration. A deployment definition for the same URI continues to apply.

Administrators can inspect this process’s chain settings with `GET /api/v1/admin/settings/blockchain`. A newly started process reports a disabled runtime configuration. The same admin page reads `GET /api/v1/admin/blockchain/health`, which checks the configured provider for its latest block and reports availability. The administrator can update process-local chain settings with `PUT` on the settings route. Each successful update reports the current signer and audits the submitted field names. During a rollout, direct the update to each API process that will serve chain-backed traffic. Verify its settings and read both `/api/v1/admin/policies` and `/api/v1/admin/groups` through that process before adding it to the pool. A process configured with an unreachable chain endpoint returns 503 for those catalogs while a peer still using PostgreSQL can return 200. When returning to PostgreSQL, disable the runtime chain configuration on each affected process and verify the expected catalog entries.

Administrators can read and update the password sign-in policy at `/api/v1/admin/settings/auth-policy` with `GET` and `PUT`. Set `magic_link_interval` to `never` or a whole number of hours or days from `1h` through `30d`. Enabling confirmation requires an account link base and a configured mail provider. The development environment also supports mock mail. Each update records the interval the operator replaced and the new interval. Both backends apply the stored cadence to subsequent password sign-ins.

Wallet sign-in starts with `POST /api/v1/auth/wallet/challenge`. Submit a `wallet_address` and an optional `chain_id` (default 1). Sign the returned `message` exactly as received, including its trailing newline. Poll `GET /api/v1/auth/wallet/challenge/{challenge_id}` for its status. Submit the challenge ID and signature to `POST /api/v1/auth/wallet/verify` to receive a first-party session. Either backend can verify a challenge from the other when both use the same PostgreSQL database.

`WALLET_AUTH_DOMAIN` selects the signing domain (default `cyberdyne.local`). Challenges expire after `WALLET_CHALLENGE_TTL_SECONDS` (default 300). `RATELIMIT_WALLET_PER_MIN` sets the per-source issuance quota (default 10).

Administrators can search accounts with `GET /api/v1/admin/users`. The directory supports pagination, literal email or wallet substring search, and filters for account activity, email verification and organization. Each entry includes its linked identity count. `GET /api/v1/admin/users/{user_id}` includes identity summaries, MFA status, the most recent session activity and whether the bootstrap email list manages the account's administrator flag.

`GET /api/v1/admin/users/{user_id}/passkeys` lists the user’s active credentials across relying parties in creation order. Administrators can inspect this list even when passkey sign-in is disabled. Use `DELETE /api/v1/admin/users/{user_id}/passkeys/{passkey_id}` to revoke a lost device, including the user’s last passkey. Existing sessions stay valid. The change is recorded in both the account activity and operator audit.

Use `PUT /api/v1/admin/users/{user_id}/admin` with a JSON `is_admin` flag to grant or revoke administrator access. Operators cannot change their own role or a configuration-managed account. Demoting a stored administrator advances the account’s token cutoff.

Use `PUT /api/v1/admin/users/{user_id}/password` with a JSON `new_password` to replace an account credential and revoke its sessions. The operator audit records the reset, and account activity records how many sessions it revoked. Argon2id and legacy bcrypt credential handoffs have been verified. Deployments with a failing bcrypt provider have an open compatibility decision because Pyloros can generate a replacement hash.

Use `DELETE /api/v1/admin/users/{user_id}/mfa` to recover an account after the user loses their authenticator. A reset clears the TOTP secret and recovery codes, keeps existing sessions valid, and records the operator and prior enrollment state.

Use `POST /api/v1/admin/users` with an email and password to provision an active account with a verified email and a managed wallet. The response includes the account ID, email, wallet address and public key. The account, matching registration webhook deliveries and both audit records commit together. Concurrent registrations for the same email return one creation and one conflict. To dispatch registration hooks, set `PYLOROS_REGISTRATION_HOOK_DISPATCH=true` and bind each active registration hook to a component. Each recipient receives the event type and user ID. Only recipients opted in at both enqueue and execution also receive the email and public wallet address. An active hook without a binding, or disabled dispatch with active hooks, returns 503 and rolls back account creation.

For an existing account, `POST /api/v1/admin/users/{user_id}/wallet` returns `user_id`, `address` and `created`. Creating a wallet requires the shared `MASTER_KEY` and commits its encrypted key and operator audit event together. A sequential retry returns the existing address with `created=false`. Two overlapping first-time requests can each return a different address. The last committed address is the one stored on the account.

Bulk provisioning uses `POST /api/v1/admin/users/bulk`. Upload a UTF-8 CSV as the multipart field `file`, with `email` and `password` columns and up to 1,000 data records. The response contains creation and failure counts plus one result per record. A valid import commits its accounts, authentication events, matching webhook deliveries and batch audit together. Each successfully created account queues its registration hooks in the import transaction.

For spreadsheet exports, select comma-delimited UTF-8 CSV with the column names on the first line. UTF-8 files with a byte-order mark, quoted column names, and LF or CRLF line endings are supported. A semicolon separator, an Excel `sep=,` preamble, or a UTF-16 file produces HTTP 400 before any accounts are created. Replaying a committed import reports existing accounts as failed rows and records another batch audit. Check the created and failed counts before retrying.

The multipart form charset applies to field names and text values. Send the CSV as a part named `file` with a `filename` parameter. The importer accepts international filenames, including those sent in a legacy encoding. The CSV contents must be UTF-8 even when the enclosing form declares another charset. Sending the field as text returns a validation error.

During migration, keep the bulk import route on the existing backend while an active `user_registered` hook still needs a WebAssembly binding. Use `just hook-inventory user_registered` to check registration coverage before switching the writer. A committed edit to a hook’s source invalidates its binding, including edits made through the existing backend. If Pyloros returns 503 with `Registration hook dispatcher unavailable`, the whole import rolled back. Route the next attempt to the existing backend or bind the reviewed replacement component before resubmitting the CSV.

Administrators can inspect account sessions with `GET /api/v1/admin/sessions`. Use `user_id` to filter by account, `active_only=false` to include expired and revoked sessions, and `page` and `page_size` for pagination. The default page contains up to 20 active sessions, newest first. `DELETE /api/v1/admin/sessions/{session_id}` revokes the selected session and its remaining refresh tokens. The authentication event and operator audit entry commit in the same transaction.

Administrators can list browser origins with `GET /api/v1/admin/oauth/web-origins` and inspect a managed entry with `GET /api/v1/admin/oauth/web-origins/{origin_id}`. The list groups configured CORS, dynamic registration and fragment redirect settings by origin and includes inactive managed entries. Each managed record has its own UUID. Configured registration origins remain visible when dynamic registration is disabled. Internationalized hostnames retain their Unicode spelling in the inventory.

Register a browser origin with `POST /api/v1/admin/oauth/web-origins`. Supply a bare HTTPS origin or a loopback HTTP origin. CORS defaults to enabled and dynamic registration defaults to disabled. Fragment redirect targets must belong to the registered origin. Use `PATCH /api/v1/admin/oauth/web-origins/{origin_id}` to edit its name, flags, redirect targets or active status. The writer applies committed changes immediately. Other replicas pick them up on their refresh interval.

Use `DELETE /api/v1/admin/oauth/web-origins/{origin_id}` to deactivate a managed browser origin. Its row remains available for inspection. The writer removes its contribution to CORS, CSRF origin checks, registration redirects and external OAuth fragment redirects as soon as the deactivation and audit entry commit.

Register a protected resource with `POST /api/v1/admin/oauth/protected-resources`. Supply an HTTPS resource URI, its allowed scopes and an optional token audience. Use `PATCH /api/v1/admin/oauth/protected-resources/{entry_id}` to edit its policy and display fields. Omitted fields retain their stored values. A null audience restores the URI as the token audience, and an empty scope list clears the resource’s scope grants. Each successful write commits its audit record and publishes the new policy on the writing replica.

Use `POST /api/v1/admin/oauth/scopes` with a name and description to register a scope. Use `PATCH /api/v1/admin/oauth/scopes/{name}` to edit its description or active flag. Omitted and null fields preserve their stored values. After the scope and its audit entry commit, the writing replica publishes the current scopes, protected resources and browser origins. Discovery, token issuance, dynamic registration, browser origin checks and OAuth redirects use the committed policy even when periodic refresh is disabled.

Use `DELETE /api/v1/admin/oauth/scopes/{name}` to deactivate a managed scope. Existing client grants retain it. Once the change and its audit entry commit, the writer stops advertising the scope and accepting it for new clients. Other replicas update on their configured refresh interval. Built-in scopes are read-only.

Operators can create confidential or public applications with `POST /api/v1/admin/oauth/clients`. A successful registration returns the client identifier and a secret once, and commits the registration and operator audit entry together. The administrative API uses the issuer’s standard scopes, the deployment’s `PYLOROS_RESOURCE_SCOPE_CATALOG` and active PostgreSQL scope entries. Configure the complete application scope catalog during migration. Service client registration also works with OIDC disabled.

Operators can edit a registration with `PATCH /api/v1/admin/oauth/clients/{client_id}`. Omitted fields retain their values. For example, `{"allowed_audiences":null}` clears the audience restriction, while `{"allowed_scopes":null}` empties the scope list. Edits to self-registered clients enforce their public-client, consent, grant and scope restrictions. A failed audit write rolls back the edit.

Administrators can rotate an OAuth client secret with `POST /api/v1/admin/oauth/clients/{client_id}/rotate-secret`. The response contains the replacement secret once. The previous secret remains valid for `grace_seconds` (default 300, range 0–3600). A second rotation replaces the previous grace credential. Both backends use the hashes and deadline stored in PostgreSQL. During coexistence, serialize rotations for each client across backends. Overlapping requests can retain the original grace credential when the legacy writer finishes last.

With OIDC and `OAUTH_DCR_ENABLED` enabled, clients can self-register at `POST /api/v1/auth/oauth2/register`. Registration accepts public clients using PKCE. Loopback callbacks and HTTPS origins listed in `OAUTH_DCR_ALLOWED_REDIRECT_ORIGINS` or enabled for registration in PostgreSQL are eligible. `RATELIMIT_DCR_PER_HOUR` sets the per-address quota and defaults to 10. Registration stores the client and its administrative audit entry together. The user grants consent before a registered client receives a code.

The [token endpoint](openspec/specs/oauth-token/spec.md) accepts authorization-code and refresh-token grants with form or HTTP Basic client credentials. A refresh keeps the original session and authentication context. Pyloros recalculates scopes against the original consent and current client and resource policy, and reloads PostgreSQL authorization claims. Replaying a spent refresh token ends its session family. Configure the access and ID lifetimes with `JWT_ACCESS_TOKEN_TTL_MINUTES` and `OIDC_ID_TOKEN_TTL_MINUTES` (both default to 15), and the refresh lifetime with `JWT_REFRESH_TOKEN_TTL_DAYS` (default 30). Set `OAUTH_PROTECTED_RESOURCES` to a JSON object mapping HTTPS resource URLs to scope lists or objects with scopes and an audience override. Configured audiences take precedence over active PostgreSQL registrations. The registry refresh interval also applies to resource audiences.

Pyloros validates environment-defined resource scopes at startup, including when OIDC is disabled. The default catalog includes `openid`, `profile`, `email`, `offline_access` and `roles`. Supply additional recognized names in the space-separated `PYLOROS_RESOURCE_SCOPE_CATALOG` deployment setting. For migration, supply the reference deployment’s complete application scope catalog. This setting controls configuration validation independently of discovery and client grants.


With OIDC and `OAUTH_DEVICE_GRANT_ENABLED` enabled, a registered device client starts authorization at `POST /api/v1/auth/oauth2/device_authorization`. The response includes a verification URL, a short user code and a device code for polling. PostgreSQL stores the pending request and the digest of the device code. Set `PYLOROS_DEVICE_UI_PATH` to the deployment’s shared device-page JSON bundle to serve browser verification and decisions. Either backend can accept the signed decision ticket. The device polls the shared token endpoint with its device code. Pending polls persist the interval across issuers. An approved grant can be consumed once. A later redemption revokes the session and its refresh tokens.

During coexistence, Pyloros can handle authorization-code, refresh-token and device-code exchanges for clients using PostgreSQL IAM, and client-credentials requests for service clients. User sessions, delegated grants, profile reads and introspection resolve roles from the selected IAM authority. Changing the running process’s chain settings takes effect on the next lookup. Group membership must belong to an identity present in the provider’s inventory. The current policy and group contracts expose no identity inventory, so a successful read yields empty assignments. Failed reads leave role claims unresolved. Keep IAM administration on the existing handler during coexistence. Authorization-code and approved device-code exchanges use the same login-hook bindings and recipient privacy settings as interactive login. An unavailable dispatcher returns HTTP 503 and leaves the code retryable. Refresh and client-credentials grants produce no login event.

## Specifications

Set `PYLOROS_OPENAPI_PATH` to a deployment-owned OpenAPI 3 JSON file to publish it at `/openapi.json`. The server checks the document envelope at startup and serves the supplied bytes for the lifetime of the process. Clients can use GET to read the document or HEAD to check its length. The schema route uses the standard browser policy by default. Set `PYLOROS_OPENAPI_CSP` to supply a deployment-specific Content-Security-Policy for that route.

The [health probes](openspec/specs/health/spec.md) and [issuer discovery](openspec/specs/issuer-discovery/spec.md) specifications describe the five foundation HTTP routes. The [HTTP response spec](openspec/specs/http-responses/spec.md) covers shared browser security headers. Run `just spec-check` with OpenSpec CLI 1.13.2 to validate active changes, published specifications and the task lists in archived changes. The same checks run on pushes and pull requests.

## Comparing running services

Use `just compare <reference-url> <pyloros-url>` with two deployments configured for the same public issuer, key, scopes and feature flags. The Python 3 development tool checks status, JSON bodies and seven response headers on the five foundation routes. Pass `--oidc-disabled` for disabled discovery or `--not-ready` when both databases are unavailable or incompatible. A difference exits nonzero and identifies the affected field or header.

The [authorization-code storage contract](openspec/specs/authorization-code-storage/spec.md) defines how pending grants survive an issuer upgrade. The Rust exchange operation authenticates the registered client, checks its allowed grant, and verifies the S256 proof, redirect, resource, expiry and active user before claiming a grant. A committed replay refusal revokes the associated session and live refresh tokens.

The [grant session specification](openspec/specs/grant-sessions/spec.md) covers PostgreSQL session creation, RS256 refresh credentials and scoped ID tokens. The ID-token signer uses the calling client as its audience and includes consented profile and authorization claims. Session creation shares the authorization-code claim transaction and carries the original authentication time and methods into the new session.

The Rust access-token signer reads account, organization and entitlement claims from PostgreSQL. The caller supplies the effective resource registry, administrator email policy and any resolved role and permission claims. A resource-bound token uses the registered audience override or the resource URL. A grant without a resource uses the client’s configured audience when present. The grant-response operation creates the session and issues the consented credentials in the caller’s transaction, using one PostgreSQL IAM snapshot for both signers. Organization roles require an active membership, and permission mappings come from the calling client and eligible clients sharing the access-token audience. The code exchange commits tokens and their success audit record together. On refusal it preserves replay revocations, records a separate audit event, and returns the OAuth error even if that audit write fails.

First-party sessions can edit their phone with `PATCH /api/v1/users/me`. Send a JSON object with a `phone` string. An empty string removes the phone. A supplied string clears phone verification, including when resubmitting the current number. Omitting the field or sending null preserves verification. Phone changes are audited in the same PostgreSQL transaction.

The email-confirmation transport supports `EMAIL_PROVIDER=mock` (the default) and `EMAIL_PROVIDER=smtp`. SMTP uses `SMTP_HOST`, `SMTP_PORT` (default 587), optional `SMTP_USERNAME` and `SMTP_PASSWORD`, and `EMAIL_FROM`. Port 465 uses implicit TLS. Other ports require STARTTLS. Set `ACCOUNT_LINKS_BASE_URL` to the browser application's public base, including its mount path. The fallback is the origin of `OIDC_LOGIN_URL` or `OAUTH_POST_LOGIN_URL`.

For PostgreSQL IAM deployments, `POST /api/v1/auth/login` supports password sign-in and starts TOTP or email confirmation when required. Successful single-factor login writes the session and audit event together and returns the token pair and browser cookies. For password, passkey and second-factor sign-in, enable `PYLOROS_LOGIN_HOOK_DISPATCH` and bind each active login hook to a component. A completed session queues one event per recipient. Only recipients opted in at enqueue and execution receive the email, IP address and user agent. Missing bindings or disabled dispatch with active login hooks return 503 and roll back session creation.

The email recipient can inspect, confirm or deny a pending sign-in on Pyloros through the shared frontend. Inspection, confirmation and denial share the per-source login quota. When login rate limiting is enabled, status polling has a separate quota of 120 requests per minute per source. All four endpoints accept UTF-8, UTF-16 and UTF-32 JSON and validate the credential field before spending quota. The initiating browser polls `POST /api/v1/auth/magic-link/status` with its MFA credential. A pending challenge returns 202. Once approved, a single poll consumes it and returns the token pair and session cookies.

For password-bound TOTP challenges, the shared frontend can submit the authenticator or recovery code to `POST /api/v1/auth/mfa/verify`. Configure `MASTER_KEY` with the same value used to encrypt the existing enrollments. A successful check consumes the factor in the transaction that records the session and MFA audit event.

Services authenticate at `POST /api/v1/auth/oauth2/token` with `grant_type=client_credentials` using HTTP Basic or form credentials. The grant uses the client's configured token lifetime, scope and audience policy, and supports secret rotation. It remains available when OIDC browser sign-in is disabled.

A resource server can authenticate with a service bearer and post a token to `/api/v1/auth/introspect`. Introspection checks the submitted token’s current revocation state and resolves user membership, entitlements, roles and permissions from PostgreSQL. A service can also read its live registration at `GET /api/v1/clients/me`.

To check a service-client handoff, route registration and secret rotation to one backend and token issuance to the other. With shared PostgreSQL and signing settings, request a token with the new secret and another with the previous secret during its grace window. Use an issued token to call `GET /api/v1/clients/me` on the registration backend. Repeat with the two backends swapped.

For introspection, send the resource server's service bearer in the `Authorization` header and the token being checked in the form field `token`. A request with only the form field receives HTTP 401. An authenticated request with an invalid token receives HTTP 200 and `{"active":false}`. Both handoff directions passed these checks with OIDC disabled.

OAuth clients can submit a token to `POST /api/v1/auth/oauth2/revoke` using HTTP Basic or form credentials. Revoking a client-owned access or service token records its identifier. Revoking a client-owned refresh token ends its session and refresh family. Both backends enforce the shared PostgreSQL records when access-token revocation enforcement is enabled.

Browser sessions rotate at `POST /api/v1/auth/refresh` using a refresh cookie or JSON token. Rotation preserves the login’s authentication time and methods and reloads account claims. Set `REFRESH_REUSE_GRACE_SECONDS` (default 10, range 0–60) to tolerate another tab presenting a recently rotated token. Reuse outside that interval revokes the session and its remaining refresh tokens.

The shared frontend signs out through `POST /api/v1/auth/logout`. A valid refresh token revokes its session family. A presented access token is denylisted until expiry. Configure `ENFORCE_TOKEN_REVOCATION=true` for immediate enforcement on protected reads.

From Preferences, a first-party user can sign out on all devices through `POST /api/v1/auth/logout-all`. The operation revokes that account’s live sessions and advances its access-token cutoff. Cookie-authenticated calls require the CSRF header.

The Preferences screen reads `GET /api/v1/auth/mfa/status` with a first-party access token. The response reports the account’s authenticator enrollment and remaining unused recovery codes.

Preferences starts authenticator enrollment at `POST /api/v1/auth/mfa/totp/setup`. The response supplies a percent-encoded UTF-8 SVG of the provisioning URI. Scan the QR image or enter its Base32 secret, then confirm a current code at `POST /api/v1/auth/mfa/totp/enable`. Store the ten returned recovery codes when they are shown. `MFA_ISSUER` sets the account label in the authenticator app.

From the same Preferences screen, an enrolled account can replace its recovery codes or disable the authenticator. Both operations require a fresh authenticator code. Password accounts must also supply their password. Passwordless accounts need recent authentication on the calling session. Replacing codes invalidates the previous set immediately.

Preferences submits the current and replacement password to `POST /api/v1/auth/password/change`. A successful change returns 204, revokes every active refresh session for the account and advances its access-token cutoff. Deployments that enforce token revocation reject previously issued access tokens. The replacement hash uses the configured `PASSWORD_SCHEME`. In Argon2 mode, Pyloros can read historical Argon2i, Argon2d and Argon2id credentials that omit the version field. It interprets those records as version 16 and writes new passwords as Argon2id version 19.

Account email addresses support Unicode and unquoted local parts longer than 64 bytes when the full address fits in 254 bytes, including the IDNA domain form. The configured SMTP relay must accept the recipient for mail delivery to succeed.

The existing forgot-password form submits to `POST /api/v1/auth/password/reset-request`. Set `RATELIMIT_RESET_PER_HOUR` to configure the per-source quota (default 5). With SMTP and an account URL configured, the recipient gets a link to the existing reset form. The link expires after one hour. The form submits to `POST /api/v1/auth/password/reset-confirm`. Redemption verifies the email address, applies eligible domain-based organization membership, replaces the password and revokes existing sessions.

Submit the email verification code to `POST /api/v1/auth/verify-email` as the JSON string field `token`. The endpoint accepts UTF-8, UTF-16 and UTF-32 JSON. An invalid field type returns a 422 response containing the submitted value. Success returns an empty 204. Verification consumes the code and applies the verified email domain’s organization membership rules.

`POST /api/v1/auth/register` creates an unverified password account with a managed Ethereum wallet, emails its verification code, and returns the account ID, normalized email, public key and address. Configure `MASTER_KEY` identically across writers. `RATELIMIT_REGISTER_PER_MIN` defaults to 10 per source. With webhooks enabled, matching subscriptions receive transactional outbox rows for the delivery worker. Self-registration uses the same component bindings and recipient privacy settings as administrator account creation.

First-party sessions can download personal data from `GET /api/v1/users/me/export`. Administrators can download the same report for a specified account from `GET /api/v1/admin/users/{user_id}/export`. Each JSON attachment includes up to 1,000 rows per section, marks truncated sections, and covers the last 90 days of authentication events. Accounts with direct ReBAC assignments receive an additional section listing the client, object and relation for each assignment. Self-service downloads have a three-per-hour allowance per account. The optional `export_notes` object in the report catalog maps table names to deployment-specific section notes.

Administrators can erase an account with `DELETE /api/v1/admin/users/{user_id}`. The response reports revoked sessions, deleted and pseudonymised row counts, retained records and applicable external processors. PostgreSQL commits account removal, activity updates, operator audit and webhook enqueue together. Set `PYLOROS_ERASURE_REPORT_PATH` to a JSON file matching [the bundled report catalog](src/profile/erasure/report.json) to use deployment-specific report wording. Upgrade all component workers before enabling `PYLOROS_ERASURE_HOOK_DISPATCH` on the erasure writer. Bind every active deletion hook to a component. Each receives only the event type and erased user ID. An unbound active deletion hook or disabled dispatcher returns HTTP 503 and rolls back erasure.

Service clients with the `users:provision` scope can invite a person through `POST /api/v1/users/provision`. Send a bearer token and a JSON body containing `email` and optional `name` and `locale`. The service checks the scope against the live client registration. Accepted requests return HTTP 202 with `{"status":"accepted"}`. New accounts receive an activation link. Existing accounts receive a sign-in and reset notice. Set `PROVISION_INVITE_TTL_DAYS` (default 7, range 1–30) and `RATELIMIT_PROVISION_PER_MIN` (default 30 per client). Each process limits email delivery to once per normalized address per day. Only invitations that create a new account queue registration hooks.

A first-party session can edit its phone with `PATCH /api/v1/users/me` or `cyberauth me update --phone`. An empty phone string removes the number. Omitting it or sending null preserves its verification state. The endpoint accepts UTF-8, UTF-16 and UTF-32 JSON. Overlapping requests that each observed a changed number record their own audit events.

### Inspect legacy hook source during migration

Administrators can send `{"code":"print(context)"}` to
`POST /api/v1/admin/hooks/validate`. The endpoint checks source without
executing it. A completed check returns `valid` and `error`. Certain compiler
failures, including a duplicate parameter, return HTTP 500.

Use `POST /api/v1/admin/hooks` to save a definition. Supply `name`,
`event_type` and `code`. Use `PUT /api/v1/admin/hooks/{hook_id}` to edit
individual fields. Omitting a field or sending null on edit preserves its value.
Changing source clears the selected WebAssembly component when migration 004
is installed. Select a component built for the new source before dispatch.
The operator audit record and the definition commit in the same transaction.

Build both release binaries with `just build-release`. Deploy the matching
`pyloros-hook-worker` alongside the backend, or set
`PYLOROS_HOOK_WORKER` to its path. The HTTP handler accepts JSON envelopes up to 64 MiB, including
UTF-16 and UTF-32 requests. It sends the full decoded module to the worker. A missing or busy worker returns HTTP 503.
For local inspection, run `pyloros-hook-worker --parse-hook-source < hook.py`.

Administrators can test an installed definition with
`POST /api/v1/admin/hooks/{hook_id}/test` or `cyberauth hooks test`.
Select the hook's compiled component first. The test accepts a JSON object
with optional `context`, works on disabled definitions, and reports output,
error, success and elapsed milliseconds. The component worker accepts up to
64 KiB of context. A completed test writes an operator audit entry.
The automated delivery history contains only dispatched events.

### Validate a WebAssembly hook

Administrators can submit a binary WebAssembly component to
`POST /api/v2/admin/hooks/validate` with `Content-Type: application/wasm`.
The component must export the synchronous handler in the [hook interface](wit/hook.wit).
Version 1.0 accepts no host imports. Validation inspects the component without
executing it or installing a hook.

A successful response includes `valid`, `abi`, `size` in bytes, and the artifact's
`sha256`. HTTP 422 includes the validation error. Each process accepts two
concurrent uploads or validations (503 when busy). Uploads have a 4 MiB limit
(413) and a 30-second deadline (408).

### Build a hook from Rust

The [event-name example](examples/event-name-hook/src/lib.rs) reads a JSON
context and returns the event type followed by a newline. It decodes the selected
field and borrows the remaining values as raw JSON. On a 65,536-byte event with
an unrelated numeric array, this reduced Wasmtime fuel use from 14.56 million
to 6.18 million units. Its bindings are
generated from this repository's WIT file. To build it with the same toolchain
used for the migration check:

```sh
rustup target add wasm32-unknown-unknown
cargo install cargo-component --version 0.21.1 --locked
just build-hook-example
```

The component is written to
`target/hook-examples/wasm32-unknown-unknown/release/event_name_hook.wasm`.
Stage it and exercise it with synthetic events before selecting it for a hook.

Before switching hook producers, run `just hook-inventory` or `pyloros --check-hook-bindings` with `DATABASE_URL` set to a read-only PostgreSQL login. The JSON report lists each hook, its source and selected component digests, its timeout in seconds, its network permission and its personal data opt-in. A null setting means the value is unavailable. Review these settings when comparing a port with its source. Before the binding migration, every selection is null. Exit code 0 means every active hook has a selection (including an empty inventory), 2 means active hooks still need bindings, and 1 means the inventory could not be read. Pass one event name, for example `pyloros --check-hook-bindings user_registered`, to limit the report and exit code to that event. A supported event with no definitions returns 0. A misspelled event returns 1. Check component behavior and queue ownership separately before enabling delivery.

The [silent example](examples/event-name-hook/examples/silent_hook.rs) completes an event without side effects or output. Run `just build-silent-hook` to produce `target/hook-examples/wasm32-unknown-unknown/release/examples/silent_hook.wasm`. Use it for a reviewed source hook whose only behavior is to complete successfully. The starter saved by the pinned console’s New hook form was verified with this component. For a deployment, compare the saved source digest before binding. A hook created from the same form may have been edited. The v1 manual test and execution history report null for silent output and retain up to 10,000 characters when a hook writes output.

During coexistence, an operator can create, validate, edit and delete v1 definitions through Pyloros while the existing service runs unported scripts. Route manual tests for those scripts and the operations that trigger them to the existing executor. Pyloros can read their execution history from shared PostgreSQL. The registration lifecycle has been exercised with this routing and one executor per request.

For a v1 manual test with a selected component, inspect the response’s `success` field. The component accepts a JSON context of up to 65,536 UTF-8 bytes. When a v1 context exceeds that size, Pyloros removes formatting whitespace outside strings and retries the size check. A context whose data still exceeds the limit returns HTTP 200 with `success: false` and records a failed test in the operator audit. Whitespace outside the context object does not count toward the limit. Keep manual tests that require larger contexts on the existing executor during migration.

### Stage a hook artifact

Apply [the artifact table migration](migrations/001_hook_artifacts.sql) once through
the deployment's PostgreSQL migration owner. For example, run
`psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_hook_artifacts.sql`.

Upload the binary to `POST /api/v2/admin/hooks/artifacts` using the same credentials
and media type as validation. A first upload returns 201. Repeating it returns 200
and the same SHA-256 digest. Administrators can download the exact component from
`GET /api/v2/admin/hooks/artifacts/{sha256}`. Staged components are inactive.

### Verify a port locally

Run `just check-hook-fixture component.wasm event.json expected.json` before
uploading a reviewed component. Supply the exact event JSON bytes and the
expected worker result. For example, a silent hook returns
`{"status":"success","output":""}`. A guest-declared error uses status
`error` and its exact output string. Whitespace inside output strings matters.

The command builds the release worker, applies the dry-run deadline and prints
the component SHA-256 on success. A mismatch, invalid input or worker failure
exits unsuccessfully. Each invocation checks one fixture and works without a
database or API credentials. Run the command for each behavior you expect
from the source hook, including guest errors where applicable.

To capture expectations for a registration hook edited during migration, run
the saved source through its v1 manual test with representative contexts.
For a successful short output, copy the returned text into the fixture,
including its final newline. For an explicit exception raised by the script,
use `{"status":"error","output":"<returned error text>"}`. The v1 view
truncates long output, so use a full source output capture for those cases.

After the offline checks pass, upload the matching component and bind it with
the reviewed source digest. Repeat the manual cases through the Rust v1 API
and compare `success`, `output`, and `error`. If the binding returns 409,
read the current source and repeat the review. Once all active registration
hooks are covered, a CSV import that rolled back with the dispatcher 503 can
be retried through Rust.

### Dry-run a staged hook

Send synthetic event JSON to `POST /api/v2/admin/hooks/artifacts/{sha256}/test`
as an administrator, with `Content-Type: application/json`. A completed request
returns a JSON status of `success` or `error` with the handler's output, or
`failed` with a diagnostic for a trap, limit, or timeout. A busy or unavailable
worker returns HTTP 503.

Each dry run starts a fresh Wasmtime process with no host imports. The service
accepts two runs at once. Event and output strings have a 64 KiB limit each.
The guest has one 16 MiB linear memory. Its execution budget is one million
fuel units plus 256 per event byte, up to 17,777,216 units for a 64 KiB event.
On Linux the worker also caps its total address space at 1 GiB or the inherited limit, whichever is lower.
The five-second worker deadline includes compilation.

`just run` builds and selects the development worker. For deployment, build it
with `cargo build --manifest-path hook-worker/Cargo.toml --locked --release` and
install `pyloros-hook-worker` beside the API executable, or set
`PYLOROS_HOOK_WORKER` to its absolute path.

### Select a hook version

After staging components, apply [the version-binding migration](migrations/002_hook_bindings.sql)
through the database migration owner. An administrator can then use
`/api/v2/admin/hooks/{hook_id}/binding` to manage the selected artifact.

| Method | Operation |
| --- | --- |
| GET | Read the hook ID and selected SHA-256, or `null` for an unbound hook. |
| PUT | Select a staged version with a JSON body containing its `sha256`. |
| DELETE | Release the selection. The artifact remains available for reuse. |

When migrating a reviewed script, include `expected_source_sha256` in the PUT
body alongside the artifact's `sha256`. Hash the UTF-8 bytes of the exact
`code` string returned by the v1 hook endpoint, including all line endings.
HTTP 409 means the source changed. Read the definition again and verify the
component against the new source before retrying. A successful change records
the supplied source digest in its audit entry.

Several independently reviewed hooks may use the same component. Upload the
artifact once and bind each hook ID using that definition’s own source digest.
A local lifecycle rehearsal used one silent component for two distinct sources.
The v1 manual test returned success with null output. A separate registration
produced one successful execution with null output and an empty delivery queue.
All v1 requests in that rehearsal went to the Rust backend. For new or edited
scripts, complete the review and binding before directing their events to Rust.

Each explicit binding change records its previous and new digest in the administrator audit log.
Repeating a completed change returns the current selection. The hook's existing
enabled flag, event, privacy settings and source are preserved.

Apply [the source-edit trigger migration](migrations/004_invalidate_edited_hook_bindings.sql)
after migrations 001–003 and before routing hook events to Rust. Every database
role that edits hook source needs DELETE on the binding table and SELECT on its
hook_id column. Check existing selections against the current source before
enabling dispatch. Earlier bindings contain no record of the source they replaced.

A committed source edit from either writer clears that hook’s selection. Stage
and bind the component corresponding to the edited source before resuming
dispatch. Settings-only edits retain the selection. Deliveries queued before
the edit still run their pinned component.

### Deliver entitlement hooks

Apply [the delivery queue migration](migrations/003_hook_deliveries.sql) after the
binding migration. On the Rust deployment that owns billing mutations, enable
`HOOKS_ENABLED=true` and `PYLOROS_STORE_HOOK_DISPATCH=true` and install the hook
worker. Bind every active grant or revocation hook to its staged component.

Stripe, Google Play and App Store billing writes queue each matching hook in the
entitlement transaction. Delivery uses the version selected at that time and the
hook's timeout. A missing binding keeps the billing event retryable. A worker
outage after commit retains the queued work. The operator console shows successful
output, guest failures and timeouts in the existing execution history.

Administrator grants and withdrawals use the same worker and queue. Enable
`PYLOROS_ADMIN_ENTITLEMENT_HOOK_DISPATCH=true` on the deployment serving those
writes, with `HOOKS_ENABLED=true`. The store and administrator switches can be
rolled out independently. For an organization grant the event carries its
organization ID and a null user ID. Renewing a grant or repeating a withdrawal
delivers an event for each committed administrator action. The audit record,
entitlement change and queued deliveries commit together.

### Assign a component delivery worker

By default, a process with hooks enabled consumes queued component deliveries when any producer is enabled. Set `PYLOROS_COMPONENT_WORKER_ENABLED=false` on a publisher to leave execution to another replica. A dedicated worker can set `HOOKS_ENABLED=true` and `PYLOROS_COMPONENT_WORKER_ENABLED=true` to drain queued deliveries with all producers disabled. Keep a compatible Rust worker available until pending component deliveries have finished during rollback.

### Deliver PostgreSQL role hooks

Enable `HOOKS_ENABLED=true` and `PYLOROS_ROLE_HOOK_DISPATCH=true` on the
deployment writing PostgreSQL role assignments. Bind each active role hook to
its component. Administrator and delegated writes queue an event with the
subject user, resolved client and role key. Scoped assignments also include
the organization ID. Removing an organization membership queues one revocation
per withdrawn scoped role. Audit, membership and delivery changes commit together.
