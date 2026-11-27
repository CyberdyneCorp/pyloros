## ADDED Requirements

### Requirement: Enroll an authenticator
A first-party user SHALL be able to start authenticator enrollment, receiving a secret, provisioning URI and QR image. A pending seed SHALL be encrypted at rest and SHALL become active only after a valid authenticator code is confirmed.

#### Scenario: Confirm pending enrollment
- **WHEN** the account owner confirms a pending seed with an unused valid time step
- **THEN** enable the authenticator, consume the step, record the enrollment and return ten fresh single-use recovery codes, storing only their digests.

#### Scenario: Retry setup
- **WHEN** setup is requested again before confirmation
- **THEN** replace the pending seed. Once enabled, further setup and confirmation requests return a conflict.
