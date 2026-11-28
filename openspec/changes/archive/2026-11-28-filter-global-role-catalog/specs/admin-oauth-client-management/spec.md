## ADDED Requirements

### Requirement: Read global PostgreSQL roles independently of scoped groups
The PostgreSQL role catalog SHALL omit organization-qualified groups before computing per-role member counts. Only global roles owned by the client SHALL count toward its creation limit.

#### Scenario: Recover an existing oversized role catalog
- **WHEN** a client with 65 global roles retires two roles and recreates one of them
- **THEN** the catalog contains 64 roles and the recreated role starts with no assigned permissions

#### Scenario: Scoped groups coexist with global roles
- **WHEN** the administrator or service reads the global catalog for a client that also has organization-scoped groups
- **THEN** return only that client's global roles, with each membership count taken from its global group
