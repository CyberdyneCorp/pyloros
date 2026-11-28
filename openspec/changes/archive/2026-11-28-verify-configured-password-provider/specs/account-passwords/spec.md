## ADDED Requirements

### Requirement: Verify the shipped password provider
The release executable SHALL provide an offline check of the configured account password scheme using synthetic credentials.

#### Scenario: Check a configured provider
- **WHEN** an operator invokes the provider check
- **THEN** exercise current hash creation and verification, a historical hash, wrong-password refusal and missing-account refusal; report the scheme and outcomes without disclosing credentials or hashes

#### Scenario: Unusable provider configuration
- **WHEN** the configured scheme is unsupported or a check fails
- **THEN** exit unsuccessfully
