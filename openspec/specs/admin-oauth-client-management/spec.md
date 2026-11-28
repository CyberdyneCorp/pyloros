# admin-oauth-client-management Specification

## Purpose
Define how operators provision, edit, rotate and deactivate shared OAuth client registrations.

## Requirements

### Requirement: Maintain OAuth client registrations

The issuer SHALL allow an authorized operator to create, update, rotate the secret of and deactivate a client using the existing administrative REST contract.

#### Scenario: Provision an application

- **WHEN** an operator submits a valid registration
- **THEN** return the client metadata and newly issued credential, persist the credential hash and record the operator action without secret material.

#### Scenario: Edit a registration

- **WHEN** an operator changes a subset of fields
- **THEN** apply the accepted changes, preserve omitted fields, and record which fields were submitted.

#### Scenario: Roll a credential across backends

- **WHEN** an operator rotates a secret
- **THEN** return the replacement once and enforce the configured grace period for the previous credential on both services.

#### Scenario: Deactivate an application

- **WHEN** an operator deactivates a known client
- **THEN** retain the registration and audit history and enforce its inactive status on subsequent credential use.

#### Scenario: A deactivation is retried

- **WHEN** an operator repeats a successful deactivation
- **THEN** return an empty success response, keep the client inactive and record the operator action in the same audit chain.

#### Scenario: The audit write fails

- **WHEN** the service cannot record a deactivation in the administrative audit chain
- **THEN** the request fails and the client retains its previous active state.

#### Scenario: Rotation fails before the audit commits

- **WHEN** recording the operator action fails during a rotation
- **THEN** return a failure and preserve the current credential, previous credential and grace deadline.

#### Scenario: Rotate twice on Pyloros

- **WHEN** two rotations of the same registration commit on Pyloros
- **THEN** the second replacement is current, and only the immediately preceding replacement is eligible for its grace period.

#### Scenario: Create a service client with browser sign-in disabled

- **WHEN** an authorized operator registers a valid service application with OIDC disabled
- **THEN** create the client and its audit entry and return the issued credential.

#### Scenario: Apply changes to the scope catalog

- **WHEN** the active custom scope catalog refreshes
- **THEN** creation accepts newly active scopes and rejects scopes removed from the effective catalog.

#### Scenario: Distinguish an omitted field from an explicit null

- **WHEN** an operator submits a partial update
- **THEN** retain omitted values, apply the established null semantics of each submitted field and audit the names of recognized submitted fields.

#### Scenario: Preserve the limits of a self-registered client

- **WHEN** an operator edits a dynamic client
- **THEN** enforce the public-client, consent, grant and scope restrictions while allowing eligible changes.

#### Scenario: Edit a legacy registration

- **WHEN** an operator changes a field unrelated to a previously stored redirect or scope
- **THEN** preserve the legacy registration and apply current field validation when the operator explicitly resubmits the redirect or scope.

#### Scenario: An update cannot be audited

- **WHEN** the administrative audit write fails after the service validates a partial update
- **THEN** return a failure and leave the client registration unchanged.

### Requirement: Replace role permissions
The service SHALL allow an administrator to replace the permissions of an existing global role with a set of registered keys belonging to that client and audit the resulting set.

#### Scenario: Clear the grants
- **WHEN** the administrator submits an empty list
- **THEN** all grants for that role are removed and the audit entry records an empty list

#### Scenario: Replacement cannot commit
- **WHEN** a permission is unknown or audit persistence fails
- **THEN** the stored mapping remains intact

#### Scenario: Two Pyloros writers replace one role
- **WHEN** both replacements complete successfully
- **THEN** the stored set equals the last committed replacement

### Requirement: Maintain the client permission catalog
Administrators SHALL be able to add uniquely named permissions for active clients and remove an existing permission together with every role assignment to that key in the same client.

#### Scenario: Register a permission
- **WHEN** an operator submits a valid new key and the catalog has capacity
- **THEN** persist its optional description, record the operator action and return the created permission

#### Scenario: Retire an assigned key
- **WHEN** an operator removes a key used by several roles
- **THEN** the catalog and all affected role mappings reflect the removal on the next read

#### Scenario: Audit fails
- **WHEN** the audit write fails during a catalog change
- **THEN** roll back the catalog and mapping changes

### Requirement: Create a PostgreSQL client role

An authenticated operator SHALL be able to create a global role in an active client catalog with an optional description. The service SHALL enforce the 64-role limit per client, reject duplicate keys, clear any previous permission mapping for a newly created role and audit successful creation atomically.

#### Scenario: Reuse an available key

- **WHEN** an operator creates an available role key for an active client using PostgreSQL IAM
- **THEN** the API returns the new role with zero members, and its permission mapping is empty

#### Scenario: Audit write fails

- **WHEN** the audit record cannot be persisted
- **THEN** the role creation and mapping cleanup roll back together

### Requirement: Remove a PostgreSQL client role

An operator SHALL be able to remove a role and its organization assignments from an active client. The service SHALL remove its permission mapping and record the deletion atomically.

#### Scenario: Only an organization assignment remains

- **WHEN** the requested role has an organization group and no global group
- **THEN** deletion succeeds and removes that assignment

#### Scenario: The role does not exist

- **WHEN** no matching global or organization group exists
- **THEN** the operation returns a missing-role error and preserves any existing mapping

### Requirement: Decode large role permission replacement documents
The operator and delegated role permission replacement endpoints SHALL process valid UTF-8, UTF-16 and UTF-32 JSON envelopes exceeding two MiB under the existing authentication and catalog rules.

#### Scenario: Padded replacement
- **WHEN** an authorized caller submits an otherwise valid mapping in a padded JSON envelope exceeding two MiB
- **THEN** return the replaced mapping and persist the selected permissions

#### Scenario: Unauthenticated replacement
- **WHEN** a caller without credentials submits a valid padded mapping
- **THEN** apply the same authentication response as for a compact mapping

#### Scenario: Invalid large mapping
- **WHEN** an authorized caller submits more than 256 permission entries in a padded document
- **THEN** return the list validation error and preserve the previous mapping

### Requirement: Decode catalog entry creation requests
The operator and delegated client role and permission creation routes SHALL accept UTF-8, UTF-16 and UTF-32 documents larger than two MiB. The service SHALL validate the submitted key and description before saving the entry.

#### Scenario: Unicode catalog description
- **WHEN** an authorized caller submits a valid entry in a padded Unicode document
- **THEN** create the entry and preserve its description on subsequent reads

#### Scenario: Unrelated numeric field
- **WHEN** a valid entry includes an ignored field containing a non-finite number
- **THEN** create the entry using the recognized fields

#### Scenario: Non-finite description
- **WHEN** an authorized caller supplies a non-finite number as the description
- **THEN** return the reference HTTP 500 response for an unrepresentable validation error and leave the catalog unchanged

### Requirement: Match IAM numeric handling during role mapping replacement
Both role permission replacement routes SHALL apply the IAM numeric input rules and preserve the current mapping when parsing or validation fails.

#### Scenario: Integer exceeds decoder capacity
- **WHEN** a caller submits a mapping document containing an integer with more than 4300 decimal digits, even in an ignored field
- **THEN** respond with a body parsing error and retain the prior permission set

#### Scenario: Non-finite value outside the permission list
- **WHEN** an authorized caller submits valid permissions and an unrelated field containing a non-finite number
- **THEN** apply the requested permission set

#### Scenario: Non-finite value in a validation diagnostic
- **WHEN** producing the validation diagnostic would require returning a non-finite value in the error body
- **THEN** return the unhandled error response and retain the prior permission set

### Requirement: Read global PostgreSQL roles independently of scoped groups
The PostgreSQL role catalog SHALL omit organization-qualified groups before computing per-role member counts. Only global roles owned by the client SHALL count toward its creation limit.

#### Scenario: Recover an existing oversized role catalog
- **WHEN** a client with 65 global roles retires two roles and recreates one of them
- **THEN** the catalog contains 64 roles and the recreated role starts with no assigned permissions

#### Scenario: Scoped groups coexist with global roles
- **WHEN** the administrator or service reads the global catalog for a client that also has organization-scoped groups
- **THEN** return only that client's global roles, with each membership count taken from its global group

### Requirement: Honor committed catalog capacity across writer changes
After a drained writer switch, role and permission creation SHALL use the committed global role or permission count for the client, regardless of whether the caller uses the administrator or delegated API.

#### Scenario: Outgoing writer commits the final key
- **WHEN** the incoming writer receives a different valid key after the outgoing writer fills the catalog
- **THEN** return HTTP 409 and preserve the committed catalog and audit

#### Scenario: Outgoing final key rolls back
- **WHEN** the outgoing creation rolls back and the incoming writer receives a valid new key
- **THEN** allow creation in the available slot and record the incoming caller's audit
