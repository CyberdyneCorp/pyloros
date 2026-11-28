## ADDED Requirements

### Requirement: Inspect pending deliveries for a selected hook
Operators SHALL be able to select a single hook UUID with the queue inspection command. It SHALL count all committed delivery rows for that hook across event types, including delayed work, and return the usual pending count and exit status.

#### Scenario: Hooks share an event
- **WHEN** two hooks have pending deliveries for the same event and an operator selects one hook
- **THEN** report only that hook’s pending deliveries

#### Scenario: A deletion is still open
- **WHEN** a transaction has deleted a delivery for the selected hook and has yet to commit
- **THEN** the delivery remains in the observed count

#### Scenario: Invalid hook selection
- **WHEN** the hook UUID is invalid, missing or combined with other arguments
- **THEN** fail without printing a pending count
