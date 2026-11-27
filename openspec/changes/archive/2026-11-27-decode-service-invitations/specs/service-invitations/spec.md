## ADDED Requirements

### Requirement: Accept invitations from authorized services
The service SHALL require a client credential with the active provisioning scope to invite a user. It SHALL decode Unicode JSON before authorization and validate the address and optional name and locale after authorization. Additional properties SHALL be ignored on otherwise valid requests, including documents over two MiB.

#### Scenario: New address
- **WHEN** an authorized service invites a new address with a valid document
- **THEN** create the account, issue its invitation and return HTTP 202

#### Scenario: Existing address
- **WHEN** an authorized service invites an existing address eligible for delivery
- **THEN** send the existing-account reset message and return the same acceptance response

#### Scenario: Invalid optional field
- **WHEN** an authorized service supplies a finite number as a name or locale
- **THEN** return a field validation error with the submitted numeric value
