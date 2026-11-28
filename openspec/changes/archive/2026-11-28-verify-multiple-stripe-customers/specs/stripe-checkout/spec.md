## ADDED Requirements

### Requirement: Select an owned customer when multiple mappings exist
When multiple Stripe customer IDs belong to the authenticated account, hosted checkout SHALL supply one of those IDs and the account UUID as the client reference. Selection among the owned IDs is unspecified.

#### Scenario: Storage order changes
- **WHEN** PostgreSQL reorganizes the mapping table between checkout requests
- **THEN** either owned customer remains eligible and another account’s customer remains ineligible

#### Scenario: A hosted checkout is created after a repurchase
- **WHEN** two purchases under distinct customer IDs have granted the same account the same product and plan
- **THEN** creating the next hosted checkout leaves the existing grant and its latest purchase reference unchanged
