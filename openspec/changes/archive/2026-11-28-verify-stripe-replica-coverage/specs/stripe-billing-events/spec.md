## ADDED Requirements

### Requirement: Verify coverage of a named webhook pool
The route probe SHALL support an optional mode that requires successful samples from every expected upstream as well as success for each individual request. It SHALL identify missing upstreams on standard error and retain the sample list on standard output.

#### Scenario: Repeated requests reach one member of a two-member pool
- **WHEN** every response passes the individual checks but one expected upstream is absent
- **THEN** the coverage check exits unsuccessfully and names the missing upstream

#### Scenario: Every member is observed
- **WHEN** every sample passes and every expected upstream appears
- **THEN** the coverage check exits successfully
