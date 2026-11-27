# http-responses Specification

## Purpose

Give browsers consistent instructions for handling API responses and enforcing secure transport.

## Requirements

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

### Requirement: Cookie-authenticated writes
The service SHALL check cookie-authenticated POST, PUT, PATCH and DELETE requests before dispatch. A supplied Origin SHALL match the request origin or a configured or registered frontend origin. The configured CSRF cookie and X-CSRF-Token header SHALL match. Read requests and explicit bearer-authenticated requests SHALL remain available independently of that cookie.

#### Scenario: Untrusted browser origin
- **WHEN** a protected cookie-authenticated request supplies an unapproved origin
- **THEN** the server returns 403 before the request reaches its handler

#### Scenario: Missing double-submit token
- **WHEN** a protected request has an accepted origin and lacks the matching cookie or header
- **THEN** the server returns 403

#### Scenario: Authorization code exchange
- **WHEN** a client posts to the token endpoint while also carrying a browser session cookie
- **THEN** the endpoint handles the grant using its client credentials and grant checks

### Requirement: Browser session cookies
A session transport SHALL set HttpOnly access and refresh cookies and a script-readable CSRF cookie. The access and CSRF cookies SHALL use the root path and Lax same-site policy. The refresh cookie SHALL use the authentication path and Strict policy. All three SHALL use the configured domain and secure transport policy.

#### Scenario: Session credentials rotate
- **WHEN** a browser session receives a new token pair
- **THEN** the response replaces both credentials and issues a fresh CSRF cookie with the access lifetime

#### Scenario: Browser session ends
- **WHEN** the service clears the session cookies
- **THEN** it expires all three using their original names, domains and paths

### Requirement: Advertise methods on administrative OAuth errors

Administrative OAuth collection and detail routes SHALL omit the Allow header on ordinary reads and supply the existing route-specific value when refusing an HTTP method.

#### Scenario: Read an OAuth application or policy registry

- **WHEN** an operator reads a client, scope, resource or origin collection or entry
- **THEN** successful reads and authorization or lookup failures omit Allow.

#### Scenario: Refuse an unsupported method

- **WHEN** the operator sends an unsupported method to the client collection
- **THEN** return HTTP 405 with Allow set to POST.
- **WHEN** the operator sends an unsupported method to the client detail route or a scope, resource or origin route
- **THEN** return HTTP 405 with Allow set to GET.
