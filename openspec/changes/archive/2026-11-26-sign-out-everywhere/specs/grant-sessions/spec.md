## ADDED Requirements

### Requirement: Sign out across all sessions
An authenticated first-party caller SHALL be able to revoke every open session of its account. The operation SHALL advance the account’s access-token cutoff, audit the number of newly revoked sessions and clear the current browser cookies.

#### Scenario: Several devices signed in
- **WHEN** the caller signs out everywhere
- **THEN** sessions belonging to that account stop refreshing, older access credentials fail when revocation is enforced, and another account retains access.

#### Scenario: Untrusted caller
- **WHEN** the credential is absent, invalid, or issued to an OAuth client
- **THEN** refuse the operation without changing session state.
