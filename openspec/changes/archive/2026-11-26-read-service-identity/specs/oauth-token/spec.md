## ADDED Requirements

### Requirement: Read the calling service identity

The service SHALL return the current registration identity for an authenticated service bearer at GET /api/v1/clients/me.

#### Scenario: Active client

- **WHEN** an active registered client presents a valid service token
- **THEN** return the client identifier, current name, sorted granted scopes, current sorted audience allowlist or null, and the expiration timestamp.

#### Scenario: Ineligible caller

- **WHEN** the caller is missing, the credential has the wrong type, the client is inactive or deleted, or the credential fails the configured revocation check
- **THEN** return the existing unauthorized response and bearer challenge.
