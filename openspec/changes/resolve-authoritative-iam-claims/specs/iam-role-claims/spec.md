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

#### Scenario: A session outlives a provider switch

- **WHEN** the configured authority changes after a user signs in
- **THEN** profile reads, token introspection, and refreshed credentials use the authority selected at the time of the operation

#### Scenario: Failed lookup during delegated issuance

- **WHEN** the active authority cannot resolve membership during authorization-code redemption or refresh
- **THEN** credentials omit unresolved role and derived permission claims, and introspection omits those claims while reporting the valid token as active

#### Scenario: Failed lookup during a profile read

- **WHEN** an authenticated user requests their profile during an IAM lookup failure
- **THEN** the profile returns null for both global and organization roles

#### Scenario: The authority recovers

- **WHEN** a subsequent lookup succeeds and reports no memberships
- **THEN** role-bearing responses return empty global and organization assignments for the user
