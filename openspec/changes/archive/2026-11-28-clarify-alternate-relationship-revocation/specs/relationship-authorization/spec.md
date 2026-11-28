## MODIFIED Requirements

### Requirement: Decide access to a product object online
POST /api/v1/clients/me/rebac/check SHALL require a service token with rebac:check. For a known object type and permission it SHALL return an allowed boolean based on the active account and current client-owned graph. Unknown types or permissions SHALL return 422.

#### Scenario: Independent paths
- **WHEN** any direct or inherited path proves access
- **THEN** return allowed true, including when another path cycles

#### Scenario: Revocation and account eligibility
- **WHEN** the last granting path is removed or the account becomes inactive
- **THEN** a subsequent request on any replica returns allowed false

#### Scenario: Evaluation cannot finish
- **WHEN** storage is unavailable or traversal limits leave the answer undetermined
- **THEN** return 503 so the caller can refuse the protected operation

#### Scenario: Revoke one of two inherited grants
- **GIVEN** the only read grants are a user’s direct memberships on two parents, and the child inherits read access from both
- **WHEN** the membership on the first parent is removed
- **THEN** the next check on any API replica denies direct access to that parent and allows inherited access to the child through the second parent
- **WHEN** the link from the child to the second parent is also removed
- **THEN** the next check on any API replica denies read access to the child
