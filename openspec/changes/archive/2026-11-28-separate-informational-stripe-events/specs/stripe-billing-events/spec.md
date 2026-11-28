## ADDED Requirements

### Requirement: Acknowledge independent events during entitlement writes
An informational invoice or partial refund with a distinct event ID SHALL be able to complete while another transaction holds the same billing reference for an entitlement write. Grants and revocations for that reference SHALL continue to serialize. Every processed event ID SHALL remain idempotent.

#### Scenario: Invoice arrives while checkout is in progress
- **WHEN** checkout holds a subscription reference and an invoice.created event for that subscription arrives
- **THEN** the invoice can commit as processed with handled false before checkout completes

#### Scenario: Partial and full refunds during purchase
- **WHEN** a purchase holds a payment reference and both a partial and a full refund arrive with distinct event IDs
- **THEN** the partial refund can commit with handled true before the purchase finishes and the full refund waits to reconcile the grant
- **AND** a replay of the processed partial refund returns handled false
