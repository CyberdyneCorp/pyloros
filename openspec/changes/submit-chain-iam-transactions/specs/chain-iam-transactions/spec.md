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

#### Scenario: Two Rust replicas prepare policy changes for one signer

- **WHEN** two operators request chain policy mutations through Rust replicas sharing PostgreSQL and a signer
- **THEN** the second preparation waits for the first to release its signer lock before looking up the pending nonce. A rolled-back preparation also releases the lock.

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

### Requirement: Preserve provider quantities in unsigned IAM calls

The service SHALL preserve unsigned transaction quantities up to 256 bits while preparing a chain IAM mutation.

#### Scenario: Mixed provider representations

- **WHEN** the provider supplies nonce, gas, chain ID or fee values as unsigned JSON integers or hexadecimal strings with an optional `0x` or `0X` prefix
- **THEN** interpret integers as decimal and strings as hexadecimal and preserve the exact value in the unsigned transaction.

#### Scenario: Priority fee from block history

- **WHEN** the priority-fee RPC returns a provider error and the fallback history contains differently encoded block rewards
- **THEN** calculate the bounded priority fee from the decoded rewards and use it with the latest block's base fee.

### Requirement: Check the destination of a recorded IAM mutation

The receipt inspector SHALL optionally compare the receipt destination with an operator-supplied contract address before accepting reported success.

#### Scenario: Receipt belongs to another destination
- **WHEN** a matching transaction hash and successful status arrive with a different, absent or malformed destination
- **THEN** a destination-constrained inspection exits 2 and reports why the destination check failed

#### Scenario: Receipt matches the intended contract
- **WHEN** the requested hash, contract address and successful status all match
- **THEN** the inspector reports success and includes the requested contract in the report

### Requirement: Confirm ordinary group membership writes
The operator membership endpoints SHALL submit the configured group mutation and require a matching successful transaction receipt for the selected contract before committing the success audit and acknowledging the change.

#### Scenario: An operator grants or removes group membership
- **WHEN** the chain provider confirms the signed mutation for the requested group and identity
- **THEN** commit the corresponding operator audit and return the ordinary membership success response

#### Scenario: Submission or confirmation fails
- **WHEN** the provider rejects the transaction or supplies a missing, mismatched or reverted receipt
- **THEN** return an error and omit the success audit

#### Scenario: PostgreSQL rejects the audit commit after confirmation
- **WHEN** the contract successfully executes the membership change and PostgreSQL rejects the audit commit
- **THEN** return HTTP 500 and leave the confirmed chain effect available for reconciliation

#### Scenario: The submission connection loses the node's response
- **WHEN** a transport error leaves delivery of a signed group mutation uncertain
- **THEN** poll for its locally computed hash within the ordinary receipt deadline, keeping the signer lock and sending the envelope only once
- **AND** commit the success audit only when the receipt confirms success for the intended contract
