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
