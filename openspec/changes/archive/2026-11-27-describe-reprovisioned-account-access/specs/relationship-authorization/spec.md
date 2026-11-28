## MODIFIED Requirements

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
