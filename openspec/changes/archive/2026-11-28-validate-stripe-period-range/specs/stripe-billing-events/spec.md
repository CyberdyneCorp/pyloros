## ADDED Requirements

### Requirement: Reject unrepresentable billing periods
The service SHALL require the selected integer period end to represent a UTC instant from year 1 through year 9999 inclusive. A projection failure SHALL return HTTP 500 before any billing ledger or customer write.

#### Scenario: Corrected delivery after an out-of-range integer
- **WHEN** a signed event carries an out-of-range integer period, even with a valid lower-priority fallback
- **THEN** reject the event and allow a corrected delivery with the same ID to be processed once

#### Scenario: Integer exceeds the signed document decoder limit
- **WHEN** a signed document contains an integer with more than 4,300 decimal digits
- **THEN** return HTTP 400 before projecting any billing fields
