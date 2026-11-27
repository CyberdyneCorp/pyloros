## ADDED Requirements

### Requirement: End the browser session at the issuer
The service SHALL accept GET and form POST logout requests and terminate the session identified by browser cookies before resolving a return destination.

#### Scenario: Registered destination
- **WHEN** the request identifies an active client and an exactly registered post-logout URI
- **THEN** clear session cookies and redirect to that URI, appending state when supplied.

#### Scenario: Invalid destination
- **WHEN** client identity conflicts with the signed ID token or the return destination cannot be validated
- **THEN** preserve the logout effects, clear the cookies and return HTTP 400 locally.

#### Scenario: Neutral destination
- **WHEN** no destination is supplied and client identification is consistent
- **THEN** return the signed-out HTML page and clear the browser credentials.

#### Scenario: Historical ID-token hint
- **WHEN** the hint is a correctly signed ID token from the issuer with a valid user subject and single client audience
- **THEN** permit the client lookup even after token expiry. A typed session or service credential cannot identify a client through this parameter.
