## MODIFIED Requirements

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

## ADDED Requirements

### Requirement: Symmetric OAuth code exchange
A provider using HS256 SHALL sign access tokens for valid non-OpenID authorization codes and honor offline access. An exchange requiring an ID token SHALL return HTTP 500 with an OAuth server_error and consume the code. The issued session, refresh record and successful grant audit event SHALL persist, with no session bound to the consumed code.

#### Scenario: OpenID code replay
- **WHEN** a client retries a valid OpenID code following the unsupported signing response
- **THEN** redemption fails with invalid_grant
