## ADDED Requirements

### Requirement: Token exchange method errors
The token endpoint SHALL respond to unsupported HTTP methods with status 405 and Allow set to POST.

#### Scenario: Read the token endpoint
- **WHEN** a caller sends GET to the token endpoint
- **THEN** return the standard method error document with the detail Method Not Allowed
