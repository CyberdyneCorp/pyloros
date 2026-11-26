## ADDED Requirements

### Requirement: Browser session cookies
A session transport SHALL set HttpOnly access and refresh cookies and a script-readable CSRF cookie. The access and CSRF cookies SHALL use the root path and Lax same-site policy. The refresh cookie SHALL use the authentication path and Strict policy. All three SHALL use the configured domain and secure transport policy.

#### Scenario: Session credentials rotate
- **WHEN** a browser session receives a new token pair
- **THEN** the response replaces both credentials and issues a fresh CSRF cookie with the access lifetime

#### Scenario: Browser session ends
- **WHEN** the service clears the session cookies
- **THEN** it expires all three using their original names, domains and paths
