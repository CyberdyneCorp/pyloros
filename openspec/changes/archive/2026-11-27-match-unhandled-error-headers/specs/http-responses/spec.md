## MODIFIED Requirements

### Requirement: Browser protections on API responses
The HTTP server SHALL send framing, content sniffing, referrer, permissions and content security policies on successful API responses and errors handled by the application.

#### Scenario: Disabled discovery
- **WHEN** the server returns a discovery error
- **THEN** its headers forbid framing, disable MIME sniffing and restrict browser permissions in the same way as a successful health response

#### Scenario: Handled protocol error

- **WHEN** a protocol handler explicitly returns a server-error response with status 500
- **THEN** include the browser security policies for handled responses

#### Scenario: Unhandled internal failure

- **WHEN** an unhandled failure produces the generic internal-error document
- **THEN** omit the browser security policy headers

### Requirement: Deployment transport policy
The service SHALL send Strict-Transport-Security with a one-year lifetime, subdomains and preload on handled responses when running in production or when either secure-cookie setting is enabled. An unhandled internal failure SHALL omit this header.

#### Scenario: Local HTTP development
- **WHEN** both secure-cookie settings are false in development
- **THEN** the transport-security header is absent

#### Scenario: Secure deployment with an unhandled error

- **WHEN** an unhandled failure occurs on a secure deployment
- **THEN** omit the transport-security header from its error response

### Requirement: Browser origin policy
The API SHALL permit credentialed browser requests from explicitly allowed origins, expose the CSRF response header, and vary responses by origin when reflecting an origin on a handled response. Configured origins and active PostgreSQL registrations enabled for CORS SHALL contribute to the allowlist.

#### Scenario: Allowed preflight
- **WHEN** an allowed origin requests a supported method and custom headers
- **THEN** the preflight succeeds and permits the requested headers

#### Scenario: Refused preflight
- **WHEN** an unregistered origin requests credentialed access
- **THEN** the preflight is refused and the origin receives no access-control-allow-origin header

#### Scenario: Cross-origin unhandled error

- **WHEN** a cross-origin request ends in an unhandled internal failure
- **THEN** omit access-control response headers and the origin variation added by CORS
