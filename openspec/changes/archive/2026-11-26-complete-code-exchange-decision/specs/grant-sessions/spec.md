## ADDED Requirements

### Requirement: Authorization code exchange decision
The exchange service SHALL commit a successful issuance before returning credentials. It SHALL commit replay revocations before recording a refusal separately. A refusal SHALL retain its OAuth error and status if the refusal audit write fails.

#### Scenario: Unknown client
- **WHEN** client authentication fails
- **THEN** the response reports invalid_client with status 401 and the refusal has no user attribution

#### Scenario: Matched code
- **WHEN** an authenticated client presents a matching code with an incorrect verifier
- **THEN** the service returns invalid_grant and records the subject from the code

#### Scenario: Removed resource
- **WHEN** a claimed code refers to a resource removed from the registry
- **THEN** the exchange consumes the code and refuses issuance without creating a session
