## ADDED Requirements

### Requirement: Dry-run a staged component
The service SHALL allow an administrator to run a staged component with supplied event JSON using a fresh, resource-limited worker.
#### Scenario: Successful handler
- **WHEN** the staged component returns a successful string result
- **THEN** return that output without activating the hook or delivering a production event
#### Scenario: Handler failure or exhausted budget
- **WHEN** the guest returns an error, traps, exceeds its resource limits or times out
- **THEN** report the failed dry run and permit subsequent runs in a fresh worker
