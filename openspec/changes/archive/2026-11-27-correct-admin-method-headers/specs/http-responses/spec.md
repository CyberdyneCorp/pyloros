## ADDED Requirements

### Requirement: Advertise methods on administrative OAuth errors

Administrative OAuth collection and detail routes SHALL omit the Allow header on ordinary reads and supply the existing route-specific value when refusing an HTTP method.

#### Scenario: Read an OAuth application or policy registry

- **WHEN** an operator reads a client, scope, resource or origin collection or entry
- **THEN** successful reads and authorization or lookup failures omit Allow.

#### Scenario: Refuse an unsupported method

- **WHEN** the operator sends an unsupported method to the client collection
- **THEN** return HTTP 405 with Allow set to POST.
- **WHEN** the operator sends an unsupported method to the client detail route or a scope, resource or origin route
- **THEN** return HTTP 405 with Allow set to GET.
