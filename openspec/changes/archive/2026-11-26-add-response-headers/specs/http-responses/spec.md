## ADDED Requirements

### Requirement: Browser protections on API responses
The HTTP server SHALL send framing, content sniffing, referrer, permissions and content security policies on successful and unsuccessful API responses.

#### Scenario: Disabled discovery
- **WHEN** the server returns a discovery error
- **THEN** its headers forbid framing, disable MIME sniffing and restrict browser permissions in the same way as a successful health response

### Requirement: Deployment transport policy
The service SHALL send Strict-Transport-Security with a one-year lifetime, subdomains and preload when running in production or when either secure-cookie setting is enabled.

#### Scenario: Local HTTP development
- **WHEN** both secure-cookie settings are false in development
- **THEN** the transport-security header is absent
