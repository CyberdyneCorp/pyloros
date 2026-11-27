## ADDED Requirements

### Requirement: Operator role inventory
The service SHALL return the active client’s global roles in key order with their descriptions and member counts, using the selected IAM provider.

#### Scenario: Organization-specific assignments exist
- **WHEN** an operator reads a client’s catalog
- **THEN** the response lists only its global role definitions

#### Scenario: Selected provider fails
- **WHEN** the chain catalog is unavailable
- **THEN** the response reports provider failure without substituting PostgreSQL roles

#### Scenario: A group lacks its member view on the chain
- **WHEN** the provider enumerates a role but cannot read its members
- **THEN** the role remains visible with a member count of zero
