## ADDED Requirements

### Requirement: Browser origin policy
The API SHALL permit credentialed browser requests from explicitly allowed origins, expose the CSRF response header, and vary responses by origin when reflecting an origin. Configured origins and active PostgreSQL registrations enabled for CORS SHALL contribute to the allowlist.

#### Scenario: Allowed preflight
- **WHEN** an allowed origin requests a supported method and custom headers
- **THEN** the preflight succeeds and permits the requested headers

#### Scenario: Refused preflight
- **WHEN** an unregistered origin requests credentialed access
- **THEN** the preflight is refused and the origin receives no access-control-allow-origin header
