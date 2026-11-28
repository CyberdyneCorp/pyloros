## MODIFIED Requirements

### Requirement: End a browser session
The single-session logout endpoint SHALL clear browser session cookies and return 204 after successful processing of a valid request body, including when the credentials are already expired or missing. It SHALL denylist a valid presented access token until expiry and revoke the session family identified by a valid refresh token.

#### Scenario: An existing login ends
- **WHEN** the browser presents its access and refresh cookies
- **THEN** record logoff, revoke the session and its refresh credentials, denylist the access identifier and expire the cookies.

#### Scenario: Credential precedence
- **WHEN** both cookie and explicit credentials are present
- **THEN** use the refresh cookie before the JSON token and the bearer access token before the access cookie.

#### Scenario: Access token alone
- **WHEN** a valid access token is presented without a refresh token
- **THEN** denylist its identifier while leaving the session family available.

#### Scenario: PostgreSQL rejects logout at commit
- **WHEN** PostgreSQL explicitly rejects the transaction that revokes a live browser session
- **THEN** return HTTP 500, preserve the session and refresh credentials, and leave the browser cookies in place so the caller can retry logout
