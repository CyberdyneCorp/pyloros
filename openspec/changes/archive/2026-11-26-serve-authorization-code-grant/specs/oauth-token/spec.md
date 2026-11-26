## ADDED Requirements

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
