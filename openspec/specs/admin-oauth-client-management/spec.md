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
