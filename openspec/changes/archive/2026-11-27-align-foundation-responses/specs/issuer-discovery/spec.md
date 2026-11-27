## ADDED Requirements

### Requirement: Reject unsupported discovery methods

All three discovery routes SHALL accept GET and return the service method-error response with Allow set to GET for other methods, independently of issuer availability.

#### Scenario: HEAD on discovery
- **WHEN** a client sends HEAD to the key set or either metadata route
- **THEN** return HTTP 405 with the GET allowance and an empty body.

## MODIFIED Requirements

### Requirement: Discovery availability
The service SHALL expose metadata at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` and the public key set at `/.well-known/jwks.json`. Discovery SHALL default to disabled.

#### Scenario: Disabled provider
- **WHEN** any of these three paths receives a GET while discovery is disabled
- **THEN** return HTTP 404 with the standard problem document, using OIDC disabled as its title and detail.

#### Scenario: Trailing slash on discovery
- **WHEN** a client requests the trailing-slash spelling of a discovery URL
- **THEN** return a 307 redirect to its canonical URL before evaluating issuer availability.
