## ADDED Requirements

### Requirement: Preserve password authentication time under contention

A password-only login SHALL retain the successful credential check time for its session credentials while waiting to recheck the account.

#### Scenario: Account-wide logout overlaps password verification

- **WHEN** a valid password is checked before the logout cutoff and the account lock delays session creation
- **THEN** the access token retains its original issue time and is refused when revocation is enforced

#### Scenario: Password is verified after the cutoff

- **WHEN** a single-step password login verifies in a later whole second than the account cutoff and creates a live session
- **THEN** the resulting access credential passes the account cutoff check
