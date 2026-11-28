## ADDED Requirements

### Requirement: Inspect saved IAM creation receipts
An operator SHALL be able to check a saved JSON transaction receipt against an expected hash, contract and creation kind offline. The inspection SHALL use the creation path’s identifier decoding rules and report candidate integers as decimal strings. An unsuccessful receipt, mismatched evidence or a missing identifier SHALL produce a non-success exit status.

#### Scenario: Inspect a directory receipt
- **WHEN** a matching successful group or policy creation receipt has a first log that admits one or more identifier interpretations
- **THEN** report the distinct candidates for subsequent catalog reconciliation

#### Scenario: Missing identity mint log data
- **WHEN** the matching identity mint log omits the data field and the runtime would use its historical zero fallback
- **THEN** distinguish that fallback from an identifier present in the supplied log
