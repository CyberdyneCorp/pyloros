## MODIFIED Requirements

### Requirement: Issuer metadata
When enabled, both metadata routes SHALL return HTTP 200 and the same JSON document with unique, sorted scopes. The public base SHALL use the configured issuer with trailing slashes removed, including its path prefix. If absent, it SHALL use the current request origin. Forwarded HTTPS SHALL affect this origin only for trusted proxy peers.

#### Scenario: Configuration includes an issuer path
- **WHEN** the configured issuer is https://login.example/tenant/ and scopes contain duplicates
- **THEN** both documents use https://login.example/tenant and list each scope once in sorted order

#### Scenario: Multiple request origins
- **WHEN** two origins reach an issuer without a fixed public base
- **THEN** each discovery response uses its own origin for the issuer and all endpoint URLs

## ADDED Requirements

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
