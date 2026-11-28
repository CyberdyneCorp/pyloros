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

#### Scenario: Reprovision an erased email address
- **WHEN** an administrator erases a member and provisions a new account with the same email address
- **THEN** the replacement account has a new UUID and its export contains no former assignments
- **AND** inherited access through the removed membership is denied until the client grants membership to the new UUID
- **AND** checks for the erased UUID continue to deny after that grant

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

#### Scenario: Revoke one of two inherited grants
- **GIVEN** the only read grants are a user’s direct memberships on two parents, and the child inherits read access from both
- **WHEN** the membership on the first parent is removed
- **THEN** the next check on any API replica denies direct access to that parent and allows inherited access to the child through the second parent
- **WHEN** the link from the child to the second parent is also removed
- **THEN** the next check on any API replica denies read access to the child

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

### Requirement: Evaluate model replacements at the commit boundary
A permission check SHALL use a single committed model and graph snapshot. After a model replacement returns HTTP 204, a new check on any API replica sharing the PostgreSQL primary SHALL evaluate the committed model.

#### Scenario: Remove an inherited permission rule
- **WHEN** a pending replacement retains direct membership and removes the parent traversal rule
- **THEN** a check taking its snapshot before commit sees the prior committed rule
- **AND** after commit a new check denies access derived solely from that parent while allowing direct membership

#### Scenario: Model audit rolls back
- **WHEN** recording a changed model fails and the transaction rolls back
- **THEN** subsequent checks continue to use the previously committed model and assignments

### Requirement: Open the permission snapshot in one statement
The permission check SHALL begin its PostgreSQL transaction in read-only repeatable-read mode with one statement.

#### Scenario: Prepare an inherited check
- **WHEN** a check begins evaluating a permission through a parent
- **THEN** the initial transaction statement establishes both isolation and read-only mode before any decision inputs are read

### Requirement: Resolve relationship check inputs together
After validating the calling service's grant, the check SHALL read the client's model and the subject account's eligibility in one PostgreSQL statement within its decision snapshot.

#### Scenario: Missing model for an inactive account
- **WHEN** the client has no installed model
- **THEN** return HTTP 409 regardless of account eligibility

#### Scenario: Installed model for an inactive account
- **WHEN** an inactive account is checked against an installed model
- **THEN** return HTTP 422 for an unknown permission, and return a denied decision for a known permission

### Requirement: Group membership checks on direct-only objects
When a traversal batch contains at least eight objects of the same type and permission governed by a single direct rule, the evaluator SHALL check the eligible objects for membership together within its existing client snapshot and work budget.

#### Scenario: A team grants access
- **WHEN** the account is assigned the direct relation on any team within the eligible batch prefix
- **THEN** return an allowed decision

#### Scenario: Budget ends before the granting team
- **WHEN** no eligible team grants access and remaining teams cannot be checked within the budget
- **THEN** report an unavailable decision unless another eligible path proves access

### Requirement: Preserve independent grants across membership batches
The service SHALL evaluate all eligible membership batches within the decision budget. Revoking a grant in one batch SHALL preserve access through any remaining eligible grant in another batch.

#### Scenario: Withdraw overlapping grants
- **WHEN** an application withdraws membership from a team while another team still grants the same permission
- **THEN** new checks on both replicas allow access until the last granting membership is removed

#### Scenario: A partial final batch grants access
- **WHEN** full membership batches produce no grant and a team in the final partial batch grants the permission
- **THEN** allow access if that team's rule fits the remaining budget

### Requirement: Preserve graph ownership across client lifecycle changes
The service SHALL use the active client registration and its UUID to authorize relationship checks. Deactivating a registration SHALL preserve its model and assignments. Physical deletion of that registration SHALL remove its graph.

#### Scenario: Pause and reactivate a service registration
- **WHEN** the administrator deactivates a client with direct and inherited access
- **THEN** checks starting after commit on any replica return HTTP 401 for that client's token
- **AND** reactivating the same registration restores its graph for an otherwise eligible token

#### Scenario: Replace a physically deleted registration
- **WHEN** a new registration uses the same client identifier with a new UUID
- **THEN** its authorized check returns HTTP 409 until its own model is installed
- **AND** the former registration's token cannot check the replacement graph
- **AND** other clients retain their models and assignments

### Requirement: Resolve conflicting model and assignment writes
Concurrent writes for one client SHALL leave every committed assignment valid under the committed model. Both replicas SHALL report the resulting permission decision on subsequent checks.

#### Scenario: Grant commits before model replacement
- **WHEN** a relationship grant commits before a competing model replacement that would invalidate it
- **THEN** return 204 for the grant and 409 for the replacement
- **AND** retain the assignment and its original model

#### Scenario: Model replacement commits before grant
- **WHEN** a model replacement removes a relation before a competing grant for that relation commits
- **THEN** return 204 for the replacement and 422 for the grant
- **AND** preserve the replacement model and omit the rejected assignment

#### Scenario: Retry both requests after the conflict
- **WHEN** the caller retries the same pair against the resulting state without intervening writes
- **THEN** return the same outcomes and create no additional change audit entries

### Requirement: Retire an assigned relation across replicas
When replacing a model would invalidate an existing assignment, the service SHALL evaluate the assignment against the committed state when the writer acquires the client lock. Revoking the last blocking assignment SHALL allow a subsequent replacement to succeed.

#### Scenario: Revocation commits first
- **GIVEN** one assignment blocks the proposed removal and provides the user's only path to a permission
- **WHEN** the revocation commits before the replacement
- **THEN** both writes return HTTP 204, both changes are audited, and subsequent checks on either replica deny that permission

#### Scenario: Replacement attempts to commit first
- **WHEN** the replacement encounters the last blocking assignment before its revocation commits
- **THEN** the replacement returns HTTP 409 and the old model stays installed
- **AND** the revocation succeeds under the old model and a new replacement request can install the proposed model

#### Scenario: Retry after both changes commit
- **WHEN** the caller repeats the revocation and model replacement after both changes have committed
- **THEN** both requests return HTTP 204 and neither appends another change audit

### Requirement: Bounded paired inherited lookups

The service SHALL read destinations for an individual node with two eligible inherited proofs in one bounded database statement and evaluate them in declared proof order within the existing snapshot and work budget.

#### Scenario: Second relation contains the grant
- **WHEN** the first inherited relation has no granting destination and sufficient work remains to evaluate a grant through the second relation
- **THEN** the check grants access

#### Scenario: A relation appears twice
- **WHEN** two inherited proofs use one relation with different destination permissions
- **THEN** each proof evaluates the ordered destination prefix with its own permission and consumes its normal work budget
