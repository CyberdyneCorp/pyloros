# http-responses Specification

## Purpose

Give browsers consistent instructions for handling API responses and enforcing secure transport.

## Requirements

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

### Requirement: Browser origin policy
The API SHALL permit credentialed browser requests from explicitly allowed origins, expose the CSRF response header, and vary responses by origin when reflecting an origin. Configured origins and active PostgreSQL registrations enabled for CORS SHALL contribute to the allowlist.

#### Scenario: Allowed preflight
- **WHEN** an allowed origin requests a supported method and custom headers
- **THEN** the preflight succeeds and permits the requested headers

#### Scenario: Refused preflight
- **WHEN** an unregistered origin requests credentialed access
- **THEN** the preflight is refused and the origin receives no access-control-allow-origin header
