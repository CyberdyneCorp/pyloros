## ADDED Requirements

### Requirement: Current user entitlements
GET /api/v1/users/me/entitlements SHALL authenticate the caller under the current-user profile policy and return an entitlements array of sorted, distinct product tokens. Active personal grants and active grants inherited from the active primary organization SHALL contribute. Expired grants SHALL be excluded.

#### Scenario: Personal and organization grants overlap
- **WHEN** the user and the primary organization both hold an active grant for the same product and plan
- **THEN** the product and plan appear once

#### Scenario: No grants
- **WHEN** an authenticated caller has no effective product grants
- **THEN** the endpoint returns an empty array
