## ADDED Requirements

### Requirement: Grant identity token
An OpenID grant SHALL produce an RS256 ID token whose subject is the granted user and whose audience is the calling client. It SHALL carry issuer, issuance time, expiry, and any recorded nonce and original authentication context. Other grants SHALL omit the ID token.

#### Scenario: Email and profile consent
- **WHEN** the grant includes email and profile scopes
- **THEN** available email and verification status, display name and profile image appear in the token

#### Scenario: Authorization claims
- **WHEN** the roles scope is granted and role lookup succeeds
- **THEN** the ID token includes unprefixed global and organization roles for the calling client, and includes resolved permission claims when available

#### Scenario: Unresolved roles
- **WHEN** role lookup is unavailable
- **THEN** role and permission fields are absent from the ID token
