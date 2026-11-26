## ADDED Requirements

### Requirement: User access tokens
User-grant access tokens SHALL be signed with RS256 and identify the issuer, user, session, unique token, lifetime, calling client and granted scopes. They SHALL include the effective admin flag, active personal and primary-organization entitlements, active memberships, and available role and permission claims. A missing authorization snapshot SHALL omit the unresolved claims. A bound resource SHALL determine the audience and an unregistered bound resource SHALL prevent issuance.

#### Scenario: Organization entitlements
- **WHEN** a user's active primary organization grants a product already granted to the user
- **THEN** the access token contains one entry for that product

#### Scenario: Unbound client
- **WHEN** an unbound grant's client has no default audience
- **THEN** its access token omits the audience field
