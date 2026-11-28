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
- **AND** serialize its compact JSON fields in the order `type`, `title`, `status`

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

### Requirement: Canonical API paths
Pyloros SHALL return a temporary redirect when removing trailing slashes from an otherwise unmatched URL identifies a registered API path.

#### Scenario: Alternate URL for a write
- **WHEN** a caller sends a mutation to the slash-suffixed form of a canonical route
- **THEN** return HTTP 307 with the canonical URL, the deployment request origin and the original query, before executing the mutation

#### Scenario: No matching route
- **WHEN** the URL and its canonical form are both unknown
- **THEN** return the ordinary missing-route response

### Requirement: Unknown URLs return the standard error representation
The HTTP router SHALL return the JSON Not Found problem with status 404 for unmatched URLs, including URLs whose trailing-slash variant is also unknown.

#### Scenario: Request an unknown URL
- **WHEN** a caller requests an unknown path
- **THEN** return the JSON error with type about:blank, status 404, and title and detail Not Found

#### Scenario: Request only the headers
- **WHEN** a caller sends HEAD to an unknown path
- **THEN** return 404 with the JSON content type and an empty response body

### Requirement: Select deployment assets from the migration package
The migration launcher SHALL select the packaged signed-out page, consent and device page bundles, API description and its policy, and subject-report catalog by default.

#### Scenario: Move the deployment directory
- **WHEN** the operator starts the launcher from a different working directory
- **THEN** resolve its default asset paths relative to the packaged binary

#### Scenario: Supply a deployment override
- **WHEN** the operator supplies an explicit asset setting
- **THEN** pass that setting through to the server

### Requirement: Validate the UUID URN prefix on typed fields
The shared REST UUID field validator SHALL accept the lowercase urn:uuid: prefix and reject case variants of that prefix.

#### Scenario: Read an account using a lowercase UUID URN
- **WHEN** an authorized caller uses a valid hyphenated user UUID with the lowercase URN prefix
- **THEN** resolve the same user as the unprefixed identifier

#### Scenario: Submit a case variant of the prefix
- **WHEN** a typed UUID field uses an uppercase or mixed-case URN prefix
- **THEN** return the usual uuid_parsing field error identifying the first character at position one

#### Scenario: Report the wrong final group length
- **WHEN** a braced or lowercase URN UUID has a final group of the wrong length after four correctly sized groups
- **THEN** include the submitted wrapper length in the reported final-group length

### Requirement: Classify wide integer text errors
Integer text validation SHALL report the size issue when the initial canonical signed decimal prefix exceeds 4,300 characters. If the integer requires normalization and the resulting signed decimal exceeds the same limit, the validator SHALL return the integer parsing issue. In-range representations SHALL continue to reach field-specific bounds checks.

#### Scenario: Negative integer at the signed boundary
- **WHEN** an integer field receives a minus sign followed by 4,300 digits starting with a nonzero digit
- **THEN** the issue type is int_parsing_size

#### Scenario: Explicit plus on an overlong integer
- **WHEN** an integer field receives a plus sign followed by 4,301 digits starting with a nonzero digit
- **THEN** the issue type is int_parsing and the input retains the submitted text

### Requirement: Normalize leading zero padding in integer fields
Integer text fields SHALL recognize repeated underscore separators in leading zero padding and apply field bounds to the resulting value. Validation diagnostics SHALL retain the submitted input.

#### Scenario: Select a page with padding
- **WHEN** a page parameter contains 0__2
- **THEN** return the same page as the integer 2

#### Scenario: Normalized negative value is below the minimum
- **WHEN** a page parameter contains 0-_2
- **THEN** report the lower-bound error for the negative value

#### Scenario: Repeated separator between significant digits
- **WHEN** a page parameter contains 1__2
- **THEN** return an integer parsing error

### Requirement: Diagnose malformed UUID text regardless of length
A typed REST UUID field SHALL report the first invalid character and its one-based position in the submitted text, including when the UTF-8 input exceeds 45 bytes. If all characters within the recognized wrapper are hexadecimal digits or hyphens, the validator SHALL report the applicable simple length, group count or group length.

#### Scenario: Nested wrappers
- **WHEN** a lowercase UUID URN contains a braced UUID
- **THEN** the field error identifies the opening brace at position ten

#### Scenario: Extra groups in long input
- **WHEN** a hyphenated UUID field contains more than five groups and exceeds 45 bytes
- **THEN** report the submitted group count and the expected count of five
