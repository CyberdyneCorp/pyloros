## ADDED Requirements

### Requirement: Registered client authentication
Before looking up a code, redemption SHALL authenticate an active client and require its authorization_code grant. A public client SHALL proceed to grant validation without a shared secret. A confidential client SHALL prove possession of its current secret or a previous secret whose grace period is still open.

#### Scenario: Rotation deadline
- **WHEN** a confidential client presents only its previous secret at or after its expiry
- **THEN** the service refuses client authentication

#### Scenario: Client cannot use the code grant
- **WHEN** a correctly authenticated client is registered only for client credentials
- **THEN** the service refuses the grant before looking up or consuming a code
