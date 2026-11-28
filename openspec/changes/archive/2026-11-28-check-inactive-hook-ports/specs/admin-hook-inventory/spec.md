## ADDED Requirements

### Requirement: Check bindings for inactive definitions before retirement
The binding inventory SHALL accept a leading `--include-inactive` option before any event names. In that mode it SHALL report `all_unbound` as the number of selected definitions without a binding and exit 2 if this count is positive. The default report and its active-only coverage decision SHALL remain compatible with saved reviews.

#### Scenario: Only inactive hooks lack a binding
- **WHEN** the operator checks all stored definitions and one inactive hook lacks a selection
- **THEN** report one unbound hook in total, zero active unbound hooks and exit 2

#### Scenario: Limit a retirement review to one event
- **WHEN** every definition in the selected event has a binding
- **THEN** report zero unbound definitions and exit successfully even when another event has unbound definitions
