## ADDED Requirements

### Requirement: Report hook binding coverage
A database operator SHALL be able to inspect all hooks and their selected component digests from a single read-only snapshot without starting the service or executing hooks. The report SHALL identify hooks by ID, name and event, include active state and the SHA-256 of UTF-8 source, and omit source text.

#### Scenario: Inventory before the binding migration
- **WHEN** the hook definitions exist and the binding table has yet to be installed
- **THEN** every hook is reported with a null component selection

#### Scenario: Determine active binding coverage
- **WHEN** an operator runs the check on a readable database
- **THEN** print a JSON report ordered by hook ID with the number of active unbound hooks and exit with code 2 if any exist, otherwise 0

#### Scenario: Inventory cannot be read
- **WHEN** required definitions or read access are missing
- **THEN** exit with an error distinct from incomplete coverage and emit no success report
