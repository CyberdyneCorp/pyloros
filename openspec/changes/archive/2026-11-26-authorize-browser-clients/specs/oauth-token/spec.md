## ADDED Requirements

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
