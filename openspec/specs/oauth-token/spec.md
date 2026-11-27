# oauth-token Specification

## Purpose
Issue signed credentials through the OAuth token endpoint and rotate refresh grants on their original sessions.

## Requirements

### Requirement: Authorization code exchange over HTTP
A signing-enabled issuer SHALL accept authorization code grants at POST /api/v1/auth/oauth2/token. It SHALL support HTTP Basic and form client credentials, preserve repeated resource parameters for validation, and use the same signing key advertised by discovery.

#### Scenario: Successful exchange
- **WHEN** the client presents a valid code and verifier
- **THEN** the server returns the committed grant response with Cache-Control no-store and Pragma no-cache

#### Scenario: Client authentication fails
- **WHEN** client authentication fails
- **THEN** the endpoint returns the OAuth invalid_client error with HTTP 401

#### Scenario: Discovery-only deployment
- **WHEN** an issuer is configured with only its public key
- **THEN** discovery continues to work without activating the token handler

### Requirement: Authorize a browser client
The service SHALL validate the registered client and callback, browser authentication, PKCE, scopes, resource and applicable consent before issuing an authorization code.

#### Scenario: Untrusted destination
- **WHEN** the client is unknown or disabled, or the callback fails the registered allowlist
- **THEN** return a local error without redirecting the browser or issuing a code.

#### Scenario: Native loopback client
- **WHEN** a public client's registered HTTP loopback callback differs only in its listening port
- **THEN** accept the requested callback and preserve its original value when binding the grant.

#### Scenario: Authentication needed
- **WHEN** a valid request requires a fresh sign-in
- **THEN** return the browser to the authorization request through hosted login, or return an OAuth error for silent requests.

#### Scenario: Consent needed
- **WHEN** an untrusted client requests scopes beyond the account's existing approval for the resource
- **THEN** require the user's decision before issuing a code.

#### Scenario: Authorized grant
- **WHEN** authentication, S256 PKCE, scope and resource policy, and consent requirements are met
- **THEN** issue a single-use code bound to the account, client, callback, PKCE challenge and approved scopes, preserving nonce, authentication context and resource when supplied.

#### Scenario: Resource policy refresh
- **WHEN** a protected resource is configured both locally and in PostgreSQL
- **THEN** use the local scope ceiling and audience together. For database-only resources, publish the active scope ceiling and audience from the same refresh.

#### Scenario: Unknown configured resource scope
- **WHEN** an environment-defined protected resource names a scope outside the deployment's recognized catalog
- **THEN** reject the configuration at startup, including when OIDC is disabled.

#### Scenario: Approval during a backend transition
- **WHEN** the signed consent ticket belongs to the signed-in account and its untrusted client and callback are still valid
- **THEN** approval merges the ticket scopes with prior approvals for that account, client and resource, preserving concurrent additions, and returns HTTP 303 to the original authorization request. Denial returns HTTP 303 to the validated callback with the state and leaves consent unchanged.

#### Scenario: Present interactive consent
- **WHEN** a first-party session needs to approve access and a shared consent bundle is configured
- **THEN** render the deployment’s consent page with escaped client and scope details and an issuer-signed ten-minute ticket bound to the account, client, resource, scopes and original authorization query.

#### Scenario: Encode the validated callback for HTTP transport
- **WHEN** the registered callback contains Unicode, spaces or existing percent escapes
- **THEN** encode unsafe characters as UTF-8 percent escapes in the Location header and preserve URI delimiters and existing escapes.

### Requirement: Serve OIDC UserInfo
The service SHALL resolve a bearer user access token to the current active account when the OIDC provider is enabled.

#### Scenario: Current account
- **WHEN** a valid user access credential is presented for an active subject
- **THEN** return the subject and available email, email verification status, name and picture, including for client-bound credentials.

#### Scenario: Unavailable identity
- **WHEN** the credential is missing, invalid, revoked under the configured policy or belongs to an unavailable account
- **THEN** return HTTP 401 with a Bearer challenge.

#### Scenario: Provider disabled
- **WHEN** OIDC is disabled
- **THEN** return HTTP 404 for the UserInfo operation.

### Requirement: End the browser session at the issuer
The service SHALL accept GET and form POST logout requests and terminate the session identified by browser cookies before resolving a return destination.

#### Scenario: Registered destination
- **WHEN** the request identifies an active client and an exactly registered post-logout URI
- **THEN** clear session cookies and redirect to that URI, appending state when supplied.

#### Scenario: Invalid destination
- **WHEN** client identity conflicts with the signed ID token or the return destination cannot be validated
- **THEN** preserve the logout effects, clear the cookies and return HTTP 400 locally.

#### Scenario: Neutral destination
- **WHEN** no destination is supplied and client identification is consistent
- **THEN** return the signed-out HTML page and clear the browser credentials.

#### Scenario: Historical ID-token hint
- **WHEN** the hint is a correctly signed ID token from the issuer with a valid user subject and single client audience
- **THEN** permit the client lookup even after token expiry. A typed session or service credential cannot identify a client through this parameter.

### Requirement: Issue OAuth service access tokens

The token endpoint SHALL support the client_credentials grant for registered services using the shared signing configuration and PostgreSQL records.

#### Scenario: Successful service authentication

- **WHEN** an eligible client authenticates and requests permitted scopes and an allowed audience
- **THEN** return a bearer access token with the registered lifetime, verified client identity and granted scopes. Record successful use before returning it.

#### Scenario: Default scopes

- **WHEN** an authenticated client omits scope
- **THEN** grant the registered scope set and report it in the same form as the existing endpoint.

#### Scenario: Refuse disallowed requests

- **WHEN** authentication fails, the client is disabled, the grant is unavailable, a scope or audience is disallowed, or the per-client quota is exhausted
- **THEN** return the applicable OAuth error and record the issuance decision according to the existing contract.

#### Scenario: Revoke across implementations

- **WHEN** either implementation issues a service token
- **THEN** the other implementation can revoke it for the registered client and the reference introspection endpoint reports it inactive with enforcement enabled.

### Requirement: Revoke client-owned credentials

Pyloros SHALL support the existing form-based OAuth token revocation endpoint and enforce its effects across services sharing the same PostgreSQL deployment.

#### Scenario: Revoke a refresh credential

- **WHEN** the authenticated client presents its refresh token
- **THEN** revoke the associated session and refresh family and return an empty HTTP 200 response with cache prevention headers.

#### Scenario: Revoke a user or service access token

- **WHEN** the authenticated client presents its access token
- **THEN** record the token identifier as revoked through its expiration and preserve other credentials that remain valid.

#### Scenario: Protect token ownership

- **WHEN** a client submits an unknown, expired, first-party or foreign credential
- **THEN** return the same empty success response without revoking another identity's credentials.

#### Scenario: Reject unsupported tokens and unauthorized callers

- **WHEN** the client credentials are invalid, a quota is exhausted, the token parameter is missing or a verified token has an unsupported purpose
- **THEN** return the corresponding OAuth error and preserve the stored credentials.

### Requirement: Read the calling service identity

The service SHALL return the current registration identity for an authenticated service bearer at GET /api/v1/clients/me.

#### Scenario: Active client

- **WHEN** an active registered client presents a valid service token
- **THEN** return the client identifier, current name, sorted granted scopes, current sorted audience allowlist or null, and the expiration timestamp.

#### Scenario: Ineligible caller

- **WHEN** the caller is missing, the credential has the wrong type, the client is inactive or deleted, or the credential fails the configured revocation check
- **THEN** return the existing unauthorized response and bearer challenge.

### Requirement: Rotate OAuth refresh grants

Pyloros SHALL exchange a valid OAuth refresh token for credentials on its original session through the shared token endpoint.

#### Scenario: Rotate a bound grant

- **WHEN** an eligible registered client presents its refresh token and satisfies the grant's resource policy
- **THEN** return credentials for the same user and session, constrained by original consent and current client and resource policy.

#### Scenario: Preserve authentication context

- **WHEN** a replacement token carries authentication claims
- **THEN** retain the original authentication time and methods and resolve current account and permission information.

#### Scenario: Historical records

- **WHEN** a supported refresh record predates client binding or stored scopes
- **THEN** preserve the reference behavior for that record, including client and audience claim omission where applicable.

#### Scenario: Competing or replayed requests

- **WHEN** callers submit the same refresh token more than once
- **THEN** issue at most one replacement. Reuse of an already rotated token revokes its live session family. Distinguish that replay from a request that loses the atomic rotation race.

#### Scenario: Ineligible exchange

- **WHEN** the client, credential, resource, user or session fails an eligibility check
- **THEN** return the existing OAuth error and record the applicable decision.
