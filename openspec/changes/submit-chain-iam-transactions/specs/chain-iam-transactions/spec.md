## ADDED Requirements

### Requirement: Confirm chain-backed IAM policy changes

The service SHALL submit operator policy changes to the configured IAM provider and determine their outcome from the transaction receipt.

#### Scenario: Confirmed mutation

- **WHEN** an authorized policy mutation is confirmed successfully
- **THEN** report its result through the existing API and record the operator action

#### Scenario: Reverted mutation

- **WHEN** the receipt indicates a reverted mutation
- **THEN** return an error and omit the success audit

#### Scenario: Concurrent mutations

- **WHEN** concurrent operations use the same signer and chain
- **THEN** coordinate submission so the service does not inadvertently replace its own pending transaction
