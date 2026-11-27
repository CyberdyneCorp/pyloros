## ADDED Requirements

### Requirement: Administer OAuth policy registries

The issuer SHALL support authenticated administrative reads, creation, partial updates and deactivation for the scope, protected-resource and web-origin registries through their existing REST contracts.

#### Scenario: Inspect the effective configuration

- **WHEN** an authorized operator lists registry entries or looks up an eligible identifier
- **THEN** return the expected metadata, source, status and ordering for that registry and apply supported filters.

#### Scenario: Protect deployment-owned definitions

- **WHEN** a mutation conflicts with a built-in or deployment-owned definition
- **THEN** enforce the registry's ownership and uniqueness rules and preserve the effective configuration.

#### Scenario: Apply a policy change

- **WHEN** a valid administrative mutation commits
- **THEN** persist the change and operator audit together, apply the effective policy on the writer and make it visible to other replicas through their registry refresh.

#### Scenario: Deactivate a managed entry

- **WHEN** an operator deletes a managed registry entry
- **THEN** retain the inactive administrative record and enforce the applicable scope, resource or origin policy.

#### Scenario: Publish a scope on the writing replica

- **WHEN** an administrator creates, reactivates or deactivates a scope while periodic registry refresh is disabled
- **THEN** the next discovery request on that replica reflects the committed change.

#### Scenario: Roll back a scope mutation

- **WHEN** the operator audit insert fails
- **THEN** the scope row and the catalog served by discovery retain their previous state.

#### Scenario: Submit duplicate scope registrations

- **WHEN** a scope already exists before validation
- **THEN** return HTTP 409 and preserve its registration.
- **WHEN** two requests pass the existence check before either inserts the same name
- **THEN** one returns HTTP 201 and the other returns HTTP 500, and exactly one registration and creation audit entry commit.

#### Scenario: Partially update a managed scope

- **WHEN** an operator provides a subset of the editable fields
- **THEN** preserve values for omitted or null fields and record the supplied editable fields, including explicit nulls, in the audit entry.

#### Scenario: Inspect deployment and managed protected resources

- **WHEN** the deployment configuration and a managed row define the same resource URI
- **THEN** the administrative list includes both sources, with the configured entry first, and the managed entry remains addressable by UUID even when inactive.

#### Scenario: Publish a protected-resource change on the writing replica

- **WHEN** the resource audience changes
- **THEN** newly issued access tokens for that resource carry the updated audience.
- **WHEN** deactivation commits with polling disabled
- **THEN** dynamic registration applies the updated scope ceiling immediately and refresh of a grant bound to that resource returns `invalid_grant`.
- **WHEN** the operator audit insert fails
- **THEN** the resource and its effective token and registration policies retain their prior state.

#### Scenario: Publish previously committed registry changes

- **GIVEN** another writer has registered a protected resource since this replica last refreshed its policy
- **WHEN** a local administrative scope mutation commits with polling disabled
- **THEN** dynamic client registration on this replica uses the current protected-resource scope ceiling before the next request.
