## ADDED Requirements

### Requirement: Preserve device grant state on unsupported ID-token signing
A device grant that establishes a session under HS256 and requests an ID token SHALL return the signing error and commit its grant state.

#### Scenario: Approved device requests an unsupported ID token
- **WHEN** signing the ID token is unsupported after a session has been issued
- **THEN** record the successful user grant, mark the device code consumed with an empty session binding, and return the OAuth server error
- **AND** subsequent polls refuse replay without issuing another session
