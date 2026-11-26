## ADDED Requirements

### Requirement: PostgreSQL token authorization snapshot
The issuer SHALL resolve global and organization-bound client roles from the user's PostgreSQL IAM groups. Only active memberships SHALL contribute organization-bound roles. Permission lists SHALL be sorted, deduplicated and scoped to the calling client's catalog plus active administrator-registered clients sharing the effective audience.

#### Scenario: Shared audience
- **WHEN** an organization-bound role implies a permission in an eligible audience catalog
- **THEN** that permission appears only under the matching organization

#### Scenario: Unavailable IAM
- **WHEN** the IAM group lookup fails
- **THEN** the snapshot is unresolved and the grant transaction remains usable

#### Scenario: No assignments
- **WHEN** the group lookup succeeds for a user with no role assignments
- **THEN** the resolved snapshot contains empty roles and permissions
