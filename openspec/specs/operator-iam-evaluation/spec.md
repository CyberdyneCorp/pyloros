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

### Requirement: Decode operator evaluation documents
The evaluation endpoint SHALL apply IAM JSON decoding before authentication. It SHALL ignore non-finite numeric literals in unused fields and preserve quoted text in string context values.

#### Scenario: Extra metadata on a permission check
- **WHEN** an authorized operator adds an unused numeric metadata field containing a non-finite literal
- **THEN** return the decision and explanation for the supplied identity, action, resource and context

#### Scenario: Integer literal exceeds 4,300 digits
- **WHEN** any integer literal exceeds the document limit
- **THEN** return HTTP 400 without evaluating the policy

#### Scenario: Non-finite context value
- **WHEN** rendering a context field validation error would include a non-finite number
- **THEN** return the unhandled HTTP 500 response

### Requirement: Evaluate historical PostgreSQL targets in order
Evaluation SHALL check action entries in stored order until one matches. It SHALL check resources only for a matching action and stop at the first matching resource. This applies to direct grants, inherited grants and permission boundaries.

#### Scenario: A later entry is invalid
- **WHEN** both target lists match before reaching a historical numeric entry
- **THEN** the statement contributes its effect and source to the decision

#### Scenario: A numeric target is reached
- **WHEN** evaluation reaches a numeric action or resource entry before any match in that list
- **THEN** the endpoint returns HTTP 500

#### Scenario: Historical character sequence
- **WHEN** a target entry is an array of individual characters containing a wildcard character
- **THEN** evaluate the sequence as an anchored wildcard pattern

### Requirement: Evaluate stored condition operands according to their types
The PostgreSQL evaluator SHALL apply historical condition operands in statement order after both targets match. It SHALL use the operator to interpret stored JSON values and preserve the string type of request context entries.

#### Scenario: Historical numeric operand
- **WHEN** a numeric equality condition compares the stored number seven to a context value of `"7"`
- **THEN** the condition matches, while string equality on the same operands is false

#### Scenario: Unusable context key
- **WHEN** evaluation reaches a condition whose stored key is an array or object
- **THEN** return HTTP 500
- **AND** a target mismatch or an earlier false condition skips that key without error
