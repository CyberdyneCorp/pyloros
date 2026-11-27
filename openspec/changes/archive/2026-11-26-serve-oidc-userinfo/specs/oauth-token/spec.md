## ADDED Requirements

### Requirement: Serve OIDC UserInfo
The service SHALL resolve a bearer user access token to the current active account when the OIDC provider is enabled.

#### Scenario: Current account
- **WHEN** a valid user access credential is presented for an active subject
- **THEN** return the subject and available email, email verification status, name and picture, including for client-bound credentials.

#### Scenario: Unavailable identity
- **WHEN** the credential is missing, invalid, revoked under the configured policy or belongs to an unavailable account
- **THEN** return HTTP 401 with a Bearer challenge.

#### Scenario: Provider disabled
- **WHEN** OIDC is disabled
- **THEN** return HTTP 404 for the UserInfo operation.
