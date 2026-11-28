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

### Requirement: Grant and withdraw a client-owned relationship
PUT and DELETE /api/v1/clients/me/rebac/relationships SHALL require the client’s current relationship management grant. Both operations SHALL return 204 on success, including an identical retry.

#### Scenario: Assign an account or related object
- **WHEN** an application creates a relationship
- **THEN** require a destination type allowed by the current model and an existing account for a user destination

#### Scenario: Withdraw a relationship
- **WHEN** an application removes an edge
- **THEN** remove only that exact edge in its own graph

#### Scenario: Audit failure or repeat delivery
- **WHEN** a write changes the graph
- **THEN** commit the change and its client audit together and omit additional audit records for no-op retries

### Requirement: Decide access to a product object online
POST /api/v1/clients/me/rebac/check SHALL require a service token with rebac:check. For a known object type and permission it SHALL return an allowed boolean based on the active account and current client-owned graph. Unknown types or permissions SHALL return 422.

#### Scenario: Independent paths
- **WHEN** any direct or inherited path proves access
- **THEN** return allowed true, including when another path cycles

#### Scenario: Revocation and account eligibility
- **WHEN** the last granting path is removed or the account becomes inactive
- **THEN** a subsequent request on any replica returns allowed false

#### Scenario: Evaluation cannot finish
- **WHEN** storage is unavailable or traversal limits leave the answer undetermined
- **THEN** return 503 so the caller can refuse the protected operation

### Requirement: Read broad relationship graphs efficiently
The service SHALL group bounded outgoing object-edge reads for broad permission searches in the same client-scoped snapshot used for the decision. Traversal order and the rule and edge budgets SHALL apply to every visited object, including objects without outgoing object edges.

#### Scenario: Direct membership on a leaf
- **WHEN** a queued object has a direct user grant and no outgoing object edges
- **THEN** its eligible direct rule can prove access within the remaining work budget

#### Scenario: Multiple empty branches
- **WHEN** a search processes a group of at least eight queued objects with no outgoing object edges
- **THEN** a shared read allows the search to skip individual inherited relationship queries for those objects

#### Scenario: A populated branch exceeds the batch limit
- **WHEN** the batched read returns a partial list of an object's outgoing relationships
- **THEN** evaluation uses the full per-relation lookup within its decision budget, including eligible edges beyond the partial list

### Requirement: Machine-readable relationship API contract
The project SHALL publish an OpenAPI description of the model, assignment and permission-check operations, their service scopes and their response semantics.

#### Scenario: Client follows a grant and revoke example
- **WHEN** a service installs the example model, grants a user membership and links a child collection to the parent
- **THEN** the example permission check allows the user on the child
- **AND** withdrawing the membership makes the next check deny access

### Requirement: Typed relationship commands
The operator CLI SHALL expose typed commands to install a model, grant and revoke assignments, and check a permission. Each command SHALL map to its published OpenAPI operation and use the service credential flow.

#### Scenario: Operator revokes an assignment
- **WHEN** the operator previews a revocation
- **THEN** the CLI renders the intended request without contacting the service
- **AND** a confirmed invocation sends the assignment in the DELETE body

#### Scenario: Operator checks access
- **WHEN** the operator checks a permission for a user and object
- **THEN** the CLI reports the backend decision or surfaces the HTTP failure
