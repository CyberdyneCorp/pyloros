## ADDED Requirements

### Requirement: Manage the email confirmation interval

The service SHALL allow administrators to read and change the interval for password sign-in email confirmation.

#### Scenario: Read the current cadence

- **WHEN** the administrator reads the policy before its first configuration
- **THEN** report a disabled cadence and the stored update time, or null when it has never been set.

#### Scenario: Update the cadence

- **WHEN** an authorized operator submits a supported interval
- **THEN** persist the cadence and update time and audit both the old and new interval. Subsequent password sign-ins use the committed policy.

#### Scenario: Reject an unavailable delivery configuration

- **WHEN** an operator enables periodic confirmation without a usable email configuration
- **THEN** return a conflict and retain the existing policy. Disabling confirmation remains available.

#### Scenario: Concurrent policy changes

- **WHEN** two operators read the same policy before either update completes
- **THEN** each successful audit entry contains the prior value observed by that operator.
- **WHEN** two first-time updates both observe an absent policy row
- **THEN** a single insertion and audit entry commit. The competing insertion returns a server error.
