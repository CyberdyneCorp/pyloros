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
