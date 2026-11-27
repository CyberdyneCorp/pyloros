## ADDED Requirements

### Requirement: Authoritative membership for role claims

The service SHALL derive user role claims from groups reported by the active IAM backend and restrict organization roles to active memberships.

#### Scenario: Conflicting membership sources

- **WHEN** the active backend returns an empty membership and a secondary store retains a role
- **THEN** the service emits empty role assignments for the user

#### Scenario: Authority is unavailable

- **WHEN** a role lookup fails during first-party token issuance
- **THEN** the issued token omits its role claims

#### Scenario: Organization membership removed

- **WHEN** a group identifies an organization role and the user no longer has active membership there
- **THEN** the role is excluded from the user's assignments
