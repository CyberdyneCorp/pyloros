## ADDED Requirements

### Requirement: Manage an enrolled authenticator
The service SHALL allow first-party account owners to regenerate recovery codes or disable their authenticator after verifying their password, or recent authentication on their own live session for passwordless accounts, and a valid unused authenticator step.

#### Scenario: Replace the recovery set
- **WHEN** the owner successfully requests regeneration
- **THEN** invalidate every previous recovery code and return ten fresh single-use codes, storing only their digests.

#### Scenario: Retire the authenticator
- **WHEN** the owner successfully requests disablement
- **THEN** clear the enrolled secret and all recovery codes and return an empty 204 response.

#### Scenario: Rejected proof
- **WHEN** the caller lacks the required account proof or presents a recovery code or an already consumed authenticator step
- **THEN** record the unsuccessful attempt and preserve the enrollment and recovery codes.

#### Scenario: Concurrent requests
- **WHEN** two management requests present the same authenticator step
- **THEN** at most one may commit a change to the enrollment or recovery set.
