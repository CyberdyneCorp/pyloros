## ADDED Requirements

### Requirement: Password login over HTTP
POST /api/v1/auth/login SHALL validate email and password, throttle by source and evaluate the first-party login policies. A completed login SHALL commit its session and logon audit together, then return the bearer token pair and the three session cookies. A challenged login SHALL return its method and pending credential without setting session cookies.

#### Scenario: Password login completes
- **WHEN** the account is active, the password matches and no second factor is due
- **THEN** the browser can immediately use the returned access cookie to read its current profile

#### Scenario: Required second factor
- **WHEN** TOTP or email confirmation is required
- **THEN** the response identifies the required method and holds the session until completion

#### Scenario: Stale access cookie
- **WHEN** password credentials are submitted with an existing access cookie
- **THEN** the handler authenticates the submitted credentials independently of the old session
