## ADDED Requirements

### Requirement: Checked redemption
For an authenticated client authorized to use the code grant, the application SHALL verify an unexpired code's exact redirect URI, S256 verifier, optional resource and active user before claiming it. An explicitly requested resource SHALL be a single value matching the stored resource.

#### Scenario: Binding mismatch
- **WHEN** an unused code is presented with an incorrect redirect, verifier or resource
- **THEN** the request is refused and the code remains unused

#### Scenario: Subject disabled
- **WHEN** the user is inactive at redemption
- **THEN** the request is refused and the code remains unused

### Requirement: Replayed exchange
Reuse by the bound client SHALL refuse the exchange and revoke the associated session and its live refresh tokens when one exists. Losing a concurrent claim SHALL use the same replay handling.

#### Scenario: Session family revocation
- **WHEN** the replay refusal commits
- **THEN** the winning session and its remaining refresh tokens have revocation timestamps
