## ADDED Requirements

### Requirement: Inspect entitlement records
Pyloros SHALL expose a first-party administrative directory of personal and organization grants and current subscriber statistics.

#### Scenario: Filter the directory
- **WHEN** an operator selects a user, organization or product
- **THEN** return matching grants newest first with the filtered total, owner labels, grantor email, timestamps and access token string

#### Scenario: Inspect subscriber statistics
- **WHEN** an administrator requests subscriber statistics
- **THEN** group active unexpired grants by product, plan and source, resolving the client display name before the virtual product name and falling back to the key
- **AND** sort products by descending total then ascending key
