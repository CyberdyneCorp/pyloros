# operator-iam-groups Specification

## Purpose

Give operators a consistent view of group membership counts and policy attachments from their configured IAM provider.

## Requirements

### Requirement: List IAM groups

The service SHALL allow an authenticated operator to retrieve all groups exposed by the selected IAM provider and the total number of groups.

#### Scenario: Populated inventory

- **WHEN** the operator requests the group list
- **THEN** include each group's identifier, name, description, active status, creation time, membership count, policy identifiers and chain identifier

#### Scenario: Empty inventory

- **WHEN** the provider has no groups
- **THEN** return an empty group list and a total of zero

#### Scenario: Provider change

- **WHEN** the operator changes IAM provider
- **THEN** subsequent group lists reflect the newly selected provider

### Requirement: Decode documents for group creation
Operator group creation SHALL use IAM JSON decoding before authorization. An integer literal exceeding 4,300 digits anywhere in the document SHALL return HTTP 400 without creating a group or writing an operator audit entry.

#### Scenario: A numeric literal occurs in an unused field
- **WHEN** an authorized operator submits an otherwise valid request with an unused field containing a non-finite number
- **THEN** apply the write and expose the committed change through inventory

#### Scenario: Invalid non-finite description
- **WHEN** a validation error would include a non-finite value submitted as the description
- **THEN** return the unhandled HTTP 500 response and preserve the stored state
