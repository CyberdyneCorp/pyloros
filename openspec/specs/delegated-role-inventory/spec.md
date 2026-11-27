# delegated-role-inventory Specification

## Purpose

Allow a service client to discover the roles it manages and inspect the permissions assigned to each role.

## Requirements

### Requirement: Service-client role discovery
An active service client with a valid bearer granting `roles:manage` SHALL be able to read its own role inventory and role-permission mappings.

#### Scenario: List roles
- **WHEN** the service requests `GET /api/v1/clients/me/roles`
- **THEN** return the calling client identifier and its global roles with their keys, descriptions and member counts

#### Scenario: Inspect the permissions for a role
- **WHEN** the service requests `GET /api/v1/clients/me/roles/{role_key}/permissions` for an existing role
- **THEN** return the calling client's identifier, role key and ordered permission keys

#### Scenario: Unknown role
- **WHEN** a valid role key is absent from the calling client's active role provider
- **THEN** return HTTP 404

#### Scenario: Provider outage
- **WHEN** a valid role lookup needs an unavailable runtime IAM chain
- **THEN** return HTTP 503
