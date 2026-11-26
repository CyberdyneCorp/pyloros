# Issuer discovery

## Purpose

Publish the configured issuer's capabilities and public verification key for relying parties.

## Requirements

### Requirement: Discovery availability
The service SHALL expose metadata at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` and the public key set at `/.well-known/jwks.json`. Discovery SHALL default to disabled.

#### Scenario: Disabled provider
- **WHEN** any of these three paths receives a GET while discovery is disabled
- **THEN** the response is HTTP 404 with JSON body `{"detail":"OIDC disabled"}`

### Requirement: Issuer metadata
Both metadata routes SHALL return HTTP 200 with the same JSON document when enabled. The issuer and endpoint URLs SHALL use the configured issuer base, including its path prefix. The scope list SHALL contain each configured scope once in sorted order.

#### Scenario: Configuration includes an issuer path
- **WHEN** the issuer is configured as `https://login.example/tenant/` with scopes `profile openid profile`
- **THEN** the document names issuer `https://login.example/tenant`, advertises its JWKS below that path and lists scopes `openid`, `profile` in that order

### Requirement: Optional provider features
The metadata SHALL advertise a registration endpoint only when dynamic registration is enabled. It SHALL include the device authorization endpoint and the device code grant only when the device grant is enabled.

#### Scenario: Standard grants
- **WHEN** both optional features are disabled
- **THEN** the grant list contains authorization code, refresh token and client credentials and the two optional endpoint fields are absent

### Requirement: RSA verification key
The key set SHALL publish one RSA signing key identified by `kid`, with algorithm `RS256`, use `sig`, and public modulus and exponent encoded as unpadded base64url integers.

#### Scenario: Default identifier
- **WHEN** the issuer has a configured public key and no explicit key identifier
- **THEN** the published identifier is its RFC 7638 SHA-256 JWK thumbprint

#### Scenario: Explicit identifier
- **WHEN** the operator sets `JWT_KEY_ID`
- **THEN** the key set publishes that identifier for the configured public key
