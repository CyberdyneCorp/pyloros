# operator-iam-evaluation Specification

## Purpose
Explain which policies permit or deny an action on a resource for a given identity.

## Requirements

### Requirement: Evaluate IAM access

An authorized operator SHALL be able to evaluate an identity, action, resource and request context against the selected IAM provider.

#### Scenario: Effective permission

- **WHEN** an active identity has an applicable grant and its effective policies permit the request
- **THEN** return an allow decision and the matching statements with their policy identifiers and sources

#### Scenario: Explicit denial

- **WHEN** a matching effective policy explicitly denies the requested access
- **THEN** deny the request even if another statement grants it

#### Scenario: No grant or inactive identity

- **WHEN** there is no applicable grant or the identity is inactive
- **THEN** deny the request and report the reason

#### Scenario: Permission boundary

- **WHEN** an otherwise allowed request falls outside the assigned boundary
- **THEN** deny the request and identify the boundary restriction in the explanation
