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

### Requirement: Observe a pending IAM transaction

The operator receipt check SHALL support waiting for a known transaction hash on the configured provider for up to 60 seconds.

#### Scenario: Receipt becomes available

- **WHEN** the provider initially returns an absent receipt and later returns a receipt
- **THEN** read the same transaction hash again and report the receipt outcome. Stop polling on a mismatched hash, an unrecognized status, or a revert.

#### Scenario: Receipt deadline expires

- **WHEN** the overall deadline expires before an observation completes
- **THEN** report `receipt_timeout` with exit code 2 and leave the transaction unresolved. Include in-flight reads and polling delays in this deadline.

#### Scenario: Provider rejects the lookup

- **WHEN** the provider returns a JSON-RPC error
- **THEN** terminate the check with exit code 1.
