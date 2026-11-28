## ADDED Requirements

### Requirement: Dispatch overlapping passkey paths by method
The service SHALL serve capability discovery on GET and handle PATCH and DELETE on that same path using the credential identifier rules.

#### Scenario: Attempt a credential edit at the discovery path
- **WHEN** a caller sends PATCH or DELETE to the capabilities URL
- **THEN** process the request with capabilities as the submitted credential identifier, including ordinary authentication and validation
