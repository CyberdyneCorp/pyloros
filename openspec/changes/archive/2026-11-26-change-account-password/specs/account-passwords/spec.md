## ADDED Requirements

### Requirement: Authenticated password change

A first-party account SHALL be able to change its password by supplying its current password and a replacement that satisfies the password policy.

#### Scenario: Successful change
- **WHEN** both passwords pass their respective checks
- **THEN** persist a salted replacement hash readable by both deployments, revoke all active sessions including the caller, update the access-token cutoff, audit the number of sessions revoked and return an empty 204 response.

#### Scenario: Incorrect current password
- **WHEN** the current password fails verification or the account lacks a stored password
- **THEN** return the same 401 error and record the reason without changing credentials or sessions.

#### Scenario: Concurrent change
- **WHEN** competing changes supply the same old password
- **THEN** only a caller whose proof still matches the locked account may commit.
