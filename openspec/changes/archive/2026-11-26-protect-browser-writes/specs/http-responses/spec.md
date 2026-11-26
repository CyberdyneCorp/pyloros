## ADDED Requirements

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
