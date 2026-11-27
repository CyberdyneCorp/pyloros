# operator-iam-inventory Specification

## Purpose

Give operators access to the policy statements and role session limits used by their IAM provider.

## Requirements

### Requirement: List IAM policies

An operator SHALL be able to retrieve the policy inventory from the selected IAM provider, including its total count, policy versions, active status, identifiers and ordered statements.

#### Scenario: Policy contains statements

- **WHEN** an operator lists a policy with statements
- **THEN** include each statement's effect, actions, resources, conditions and statement identifier

### Requirement: List IAM roles

An operator SHALL be able to retrieve IAM roles and the total count from the selected provider.

#### Scenario: Populated inventory

- **WHEN** an operator lists roles
- **THEN** return the role identifiers, names, descriptions, maximum session durations, active status and creation times

#### Scenario: Empty provider inventory

- **WHEN** the provider exposes no roles
- **THEN** return an empty list and zero total

### Requirement: Retrieve an IAM policy

An authenticated operator SHALL be able to retrieve a single policy by its identifier from the configured provider.

#### Scenario: Existing policy

- **WHEN** the operator opens a policy that exists on the selected provider
- **THEN** return its inventory representation with the ordered statements

#### Scenario: Unknown policy

- **WHEN** the identifier is valid and the selected provider has no matching policy
- **THEN** return a missing-resource response

#### Scenario: Provider failure

- **WHEN** the selected provider cannot read its policy catalog
- **THEN** report the provider failure
