## ADDED Requirements

### Requirement: Apply login options quota after passkey request admission
The login options endpoint SHALL preserve the caller's quota on allowed CORS preflight requests and oversized uploads. Neither request SHALL create a ceremony.

#### Scenario: One login request remains
- **GIVEN** the caller has one login options request left in the current rate-limit window
- **WHEN** an allowed preflight and a 65,537-byte upload precede a valid 65,536-byte login options request
- **THEN** the valid request succeeds and returns the challenge for exactly one newly stored login ceremony

#### Scenario: Login quota is exhausted
- **GIVEN** the caller has exhausted the current login options allowance
- **WHEN** the caller submits a 65,537-byte upload followed by a valid small request within that window
- **THEN** the uploads receive HTTP 413 and HTTP 429 respectively, neither creates a ceremony, and an allowed preflight still succeeds
