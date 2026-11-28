## ADDED Requirements

### Requirement: Verify a reviewed binding inventory
The project SHALL provide a local command to verify coverage and compare the generated inventory with a previously reviewed report for the same event selection. It SHALL fail if the inventory command fails, an active selected hook is unbound, or the report bytes differ.

#### Scenario: A fully bound hook selects a different component
- **WHEN** coverage succeeds but a selected component digest has changed since review
- **THEN** verification exits unsuccessfully

#### Scenario: A matching report contains an unbound active hook
- **WHEN** an inventory with missing active bindings exactly matches the saved file
- **THEN** verification exits unsuccessfully
