## ADDED Requirements

### Requirement: Deactivate products independently of request content
The individual product route SHALL ignore the request body for DELETE and for unsupported methods.

#### Scenario: Delete a product with an unused request body
- **WHEN** an administrator sends DELETE with a malformed or large request body for an existing key
- **THEN** deactivate the product and record its deactivation in the same transaction

#### Scenario: Reject the request before reading the body
- **WHEN** a caller sends an unsupported method or attempts deactivation without authentication
- **THEN** return the normal method or authentication error without waiting for the upload to finish

#### Scenario: Continue uploading after the response
- **WHEN** an HTTP/1.1 client continues sending the unused request body after the server has answered
- **THEN** allow the upload to finish and the client to reuse the connection
