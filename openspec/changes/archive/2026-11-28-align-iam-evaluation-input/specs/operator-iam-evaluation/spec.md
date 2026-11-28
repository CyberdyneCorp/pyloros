## ADDED Requirements

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
