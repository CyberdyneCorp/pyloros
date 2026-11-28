## ADDED Requirements

### Requirement: Consent scope descriptions follow publication
The interactive authorization page SHALL resolve managed scope descriptions from the issuer's published registry snapshot and use deployment-supplied descriptions for built-in scopes.

#### Scenario: An edit awaits publication
- **WHEN** a stored managed description changes before this process refreshes or publishes its registry
- **THEN** its consent page continues to display the previously published description

#### Scenario: The registry publishes
- **WHEN** a registry update publishes a new description on this process
- **THEN** the next consent page on this process displays the updated description
