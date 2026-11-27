## ADDED Requirements

### Requirement: Manage virtual products
Pyloros SHALL allow a first-party administrator to register, update and deactivate a virtual product and audit each accepted operation.

#### Scenario: Register a product
- **WHEN** the administrator supplies an unused, valid product key and a display name
- **THEN** return the active product, its timestamps and its optional description

#### Scenario: Edit selected fields
- **WHEN** an administrator patches a product
- **THEN** retain omitted fields, clear an explicitly null description and record which recognized fields were submitted

#### Scenario: Deactivate and reactivate
- **WHEN** the administrator deletes a product
- **THEN** deactivate the existing record and retain its key for future reactivation by patch

#### Scenario: Audit failure
- **WHEN** the audit entry for a mutation cannot be persisted
- **THEN** the product change rolls back

#### Scenario: Invalid numeric input for a nullable field
- **WHEN** a product update supplies an out-of-range number in a nullable field
- **THEN** reject the request and retain the stored product
