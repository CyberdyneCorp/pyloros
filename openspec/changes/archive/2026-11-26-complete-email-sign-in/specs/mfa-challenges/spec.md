## ADDED Requirements

### Requirement: Email challenge completion
The initiating browser SHALL present a signed MFA credential bound to the same user and email challenge. Pending and successful responses SHALL disable caching. Polls SHALL use a separate source quota.

#### Scenario: Awaiting approval
- **WHEN** a valid credential identifies an unexpired pending challenge
- **THEN** return 202 with pending status.

#### Scenario: Confirmed sign-in
- **WHEN** an active user’s approved challenge is consumed
- **THEN** issue the session once with both authentication methods and the confirmation time, set browser cookies and record the login.

#### Scenario: Refused completion
- **WHEN** the challenge expired, was denied, was consumed, or does not match the credential
- **THEN** refuse completion and record the failure.
