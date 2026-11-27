## MODIFIED Requirements

### Requirement: Grant identity token
With RSA signing configured, an OpenID grant SHALL produce an RS256 ID token whose subject is the granted user and whose audience is the calling client. It SHALL carry issuer, issuance time, expiry, and any recorded nonce and original authentication context. Other grants SHALL omit the ID token.

#### Scenario: Email and profile consent
- **WHEN** the grant includes email and profile scopes
- **THEN** available email and verification status, display name and profile image appear in the token

#### Scenario: Authorization claims
- **WHEN** the roles scope is granted and role lookup succeeds
- **THEN** the ID token includes unprefixed global and organization roles for the calling client, and includes resolved permission claims when available

#### Scenario: Unresolved roles
- **WHEN** role lookup is unavailable
- **THEN** role and permission fields are absent from the ID token

### Requirement: User access tokens
User-grant access tokens SHALL be signed with the configured session algorithm (RS256 or HS256) and identify the issuer, user, session, unique token, lifetime, calling client and granted scopes. They SHALL include the effective admin flag, active personal and primary-organization entitlements, active memberships, and available role and permission claims. A missing authorization snapshot SHALL omit the unresolved claims. A bound resource SHALL determine the audience and an unregistered bound resource SHALL prevent issuance.

#### Scenario: Organization entitlements
- **WHEN** a user's active primary organization grants a product already granted to the user
- **THEN** the access token contains one entry for that product

#### Scenario: Unbound client
- **WHEN** an unbound grant's client has no default audience
- **THEN** its access token omits the audience field
