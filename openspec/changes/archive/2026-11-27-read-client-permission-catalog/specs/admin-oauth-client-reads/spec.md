## ADDED Requirements

### Requirement: Operator permission inventory
The service SHALL let administrators list an active client's registered permissions in key order, including each description and creation time.

#### Scenario: An active client has no permissions
- **WHEN** an administrator requests its catalog
- **THEN** the response identifies the client and returns an empty list

#### Scenario: Inactive or missing client
- **WHEN** an administrator requests an unavailable client's catalog
- **THEN** the service returns a missing-client error

#### Scenario: Caller lacks administrator access
- **WHEN** the caller requests a catalog without operator privileges
- **THEN** the service refuses access before disclosing the client state
