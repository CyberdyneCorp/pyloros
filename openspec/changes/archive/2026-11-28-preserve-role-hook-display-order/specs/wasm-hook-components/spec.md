## ADDED Requirements

### Requirement: Preserve displayed role event order
The worker SHALL deliver role grant and withdrawal fields in the same order for operator and delegated assignments at either hook privacy setting.

#### Scenario: Global assignment
- **WHEN** the worker claims a global role grant or withdrawal
- **THEN** the context contains client ID, role key, event type and user ID in that order

#### Scenario: Organization assignment
- **WHEN** the worker claims an organization role grant or withdrawal
- **THEN** the organization ID appears between the role key and event type
