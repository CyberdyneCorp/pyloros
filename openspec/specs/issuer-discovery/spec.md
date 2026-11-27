# Issuer discovery

## Purpose

Publish the configured issuer's capabilities and public verification key for relying parties.

## Requirements

### Requirement: Discovery availability
The service SHALL expose metadata at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` and the public key set at `/.well-known/jwks.json`. Discovery SHALL default to disabled.

#### Scenario: Disabled provider
- **WHEN** any of these three paths receives a GET while discovery is disabled
- **THEN** return HTTP 404 with the standard problem document, using OIDC disabled as its title and detail.

#### Scenario: Trailing slash on discovery
- **WHEN** a client requests the trailing-slash spelling of a discovery URL
- **THEN** return a 307 redirect to its canonical URL before evaluating issuer availability.

### Requirement: Issuer metadata
When enabled, both metadata routes SHALL return HTTP 200 and the same JSON document with unique, sorted scopes. The public base SHALL use the configured issuer with trailing slashes removed, including its path prefix. If absent, it SHALL use the current request origin. Forwarded HTTPS SHALL affect this origin only for trusted proxy peers.

#### Scenario: Configuration includes an issuer path
- **WHEN** the configured issuer is https://login.example/tenant/ and scopes contain duplicates
- **THEN** both documents use https://login.example/tenant and list each scope once in sorted order

#### Scenario: Multiple request origins
- **WHEN** two origins reach an issuer without a fixed public base
- **THEN** each discovery response uses its own origin for the issuer and all endpoint URLs

### Requirement: Optional provider features
The metadata SHALL advertise a registration endpoint only when dynamic registration is enabled. It SHALL include the device authorization endpoint and the device code grant only when the device grant is enabled.

#### Scenario: Standard grants
- **WHEN** both optional features are disabled
- **THEN** the grant list contains authorization code, refresh token and client credentials and the two optional endpoint fields are absent

### Requirement: RSA verification key
The key set SHALL publish one public RSA signing key when RS256 is selected and an empty keys array when HS256 is selected. The RSA key SHALL have a kid, algorithm RS256, use sig, and unsigned modulus and exponent encoded as unpadded base64url integers.

#### Scenario: Default identifier
- **WHEN** an RSA issuer has no explicit key identifier
- **THEN** publish its RFC 7638 SHA-256 JWK thumbprint

#### Scenario: Explicit identifier
- **WHEN** an RSA issuer has a configured key identifier
- **THEN** publish that identifier

#### Scenario: Symmetric deployment
- **WHEN** discovery is enabled with HS256 and a configured issuer
- **THEN** both metadata endpoints advertise RS256 for ID tokens and the public key set is empty

### Requirement: Discovery scope refresh
When discovery is enabled, each replica SHALL load active PostgreSQL scope names at startup and at the configured refresh interval, which defaults to 30 seconds. Both metadata documents SHALL advertise the sorted union of these names and the configured base scopes. An interval of zero SHALL disable database loading.

#### Scenario: Catalog changes after startup
- **WHEN** a database-only scope is activated or removed
- **THEN** both documents reflect the change after the next successful refresh

#### Scenario: Registry read fails
- **WHEN** a refresh fails
- **THEN** discovery continues to serve the last successful scope set, or its base scopes if no refresh has succeeded

### Requirement: Reject unsupported discovery methods

All three discovery routes SHALL accept GET and return the service method-error response with Allow set to GET for other methods, independently of issuer availability.

#### Scenario: HEAD on discovery
- **WHEN** a client sends HEAD to the key set or either metadata route
- **THEN** return HTTP 405 with the GET allowance and an empty body.

### Requirement: Symmetric OAuth code exchange
A provider using HS256 SHALL sign access tokens for valid non-OpenID authorization codes and honor offline access. An exchange requiring an ID token SHALL return HTTP 500 with an OAuth server_error and consume the code. The issued session, refresh record and successful grant audit event SHALL persist, with no session bound to the consumed code.

#### Scenario: OpenID code replay
- **WHEN** a client retries a valid OpenID code following the unsupported signing response
- **THEN** redemption fails with invalid_grant

### Requirement: Issuer selection across grants
ID tokens and device verification URLs SHALL use the effective OIDC public base. Logout and revocation SHALL use that same base to recognize an ID-token hint. Access and refresh tokens SHALL retain the configured session issuer, including an explicit trailing slash. An explicit OIDC issuer SHALL take precedence over JWT_ISSUER for session tokens. Browser sign-in continuations SHALL return to the original request URL.

#### Scenario: Refresh from another origin
- **WHEN** a client rotates an OpenID grant on another origin without a fixed OIDC issuer
- **THEN** the new ID token names the refresh request origin and the access and refresh tokens retain their session issuer

### Requirement: Default signing algorithm selection
When the operator omits the signing algorithm the service SHALL use HS256, including deployments that have RSA key files. Under RS256 an empty key identifier SHALL select the public key thumbprint. The same RSA key supplied as SPKI, PKCS#1, or in a PEM certificate SHALL publish the same JWK.

#### Scenario: Unused RSA configuration
- **WHEN** the signing algorithm is absent and RSA file paths are set
- **THEN** discovery returns an empty key set and symmetric signing operates independently of those paths
