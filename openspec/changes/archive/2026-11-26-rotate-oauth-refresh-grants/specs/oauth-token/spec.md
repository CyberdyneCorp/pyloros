## ADDED Requirements

### Requirement: Rotate OAuth refresh grants

Pyloros SHALL exchange a valid OAuth refresh token for credentials on its original session through the shared token endpoint.

#### Scenario: Rotate a bound grant

- **WHEN** an eligible registered client presents its refresh token and satisfies the grant's resource policy
- **THEN** return credentials for the same user and session, constrained by original consent and current client and resource policy.

#### Scenario: Preserve authentication context

- **WHEN** a replacement token carries authentication claims
- **THEN** retain the original authentication time and methods and resolve current account and permission information.

#### Scenario: Historical records

- **WHEN** a supported refresh record predates client binding or stored scopes
- **THEN** preserve the reference behavior for that record, including client and audience claim omission where applicable.

#### Scenario: Competing or replayed requests

- **WHEN** callers submit the same refresh token more than once
- **THEN** issue at most one replacement. Reuse of an already rotated token revokes its live session family. Distinguish that replay from a request that loses the atomic rotation race.

#### Scenario: Ineligible exchange

- **WHEN** the client, credential, resource, user or session fails an eligibility check
- **THEN** return the existing OAuth error and record the applicable decision.
