# relationship-authorization Specification

## Purpose
Represent how accounts and application objects relate so clients can make object-level access decisions alongside role-based permissions.

## Requirements

### Requirement: Store application relationships independently of roles
The service SHALL support storing one relationship model per registered client. The database SHALL identify each relationship by its owning client, source object, relation and destination. The destination may be a user account or a product object in the same client namespace.

#### Scenario: Independent applications
- **WHEN** two clients use the same product identifiers
- **THEN** each can store and remove its own relationships independently

#### Scenario: Account removal
- **WHEN** an account is deleted
- **THEN** its direct relationships are removed from every client graph in the same transaction

#### Scenario: Client removal
- **WHEN** a registered client is deleted
- **THEN** its model and relationships are removed together

### Requirement: Include direct user relationships in account downloads
A subject export SHALL include the client, object, relation and account identifiers of direct user relationships. The same row limit and truncation indicator as other export sections SHALL apply.

#### Scenario: Administrator or account holder downloads a populated graph
- **WHEN** an authorized caller exports an account with direct assignments
- **THEN** the download includes only assignments for that account and omits object-to-object relationships

#### Scenario: No applicable relationships
- **WHEN** relationship storage is absent or the account has no direct assignments
- **THEN** the service returns the existing export sections without adding an empty graph section

### Requirement: Account for relationships in erasure receipts
Account erasure SHALL report the number of direct account relationships removed and include that count in its audited deletion total.

#### Scenario: Remove direct assignments
- **WHEN** an administrator successfully erases an account with direct relationships
- **THEN** the receipt includes the deleted relationship count and all other accounts keep their assignments

#### Scenario: Erasure fails
- **WHEN** the erasure transaction rolls back
- **THEN** the assignments remain available and no successful erasure is recorded

### Requirement: Manage the calling application’s relationship model
PUT /api/v1/clients/me/rebac/model SHALL accept a service credential explicitly granted rebac:manage. A successful replacement SHALL return 204 and preserve existing relationships.

#### Scenario: Invalid permission path
- **WHEN** a model references a missing relation, object type or target permission
- **THEN** reject it without changing the stored model

#### Scenario: Existing data conflicts
- **WHEN** an updated model would invalidate a stored assignment
- **THEN** return 409 and preserve the previous model

#### Scenario: Audited changes
- **WHEN** the model changes
- **THEN** commit the calling client’s model and audit entry together, and allow an identical retry without another change record

#### Scenario: Model exceeds the validation budget
- **WHEN** the proposed permission rules require more than 65,536 reference checks
- **THEN** return 422 and preserve the current model
