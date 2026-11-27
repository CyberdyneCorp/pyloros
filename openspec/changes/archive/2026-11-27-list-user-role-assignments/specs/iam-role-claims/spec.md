## ADDED Requirements

### Requirement: Inspect user role assignments

An operator SHALL be able to inspect an existing user’s stored global and organization role assignments through the admin API. The inventory SHALL retain duplicate assignments and include assignments to inactive organizations.

#### Scenario: Grouped inventory

- **WHEN** the user has both global and organization assignments
- **THEN** return global roles and a map of organization IDs to roles, sorted within each list by client and role key

#### Scenario: Missing chain identity link

- **WHEN** chain IAM is active and the user has no linked chain token
- **THEN** return an empty inventory without contacting the provider
