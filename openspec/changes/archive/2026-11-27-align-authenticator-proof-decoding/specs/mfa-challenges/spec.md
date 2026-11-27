## ADDED Requirements

### Requirement: Decode authenticator proofs consistently
The service SHALL decode the request document before authentication, check first-party session access before validating proof fields, and preserve submitted JSON values in field errors.

#### Scenario: Valid document with invalid proof fields
- **WHEN** a signed-in user submits a syntactically valid UTF-16 or UTF-32 document with invalid password or code values
- **THEN** return ordered field diagnostics with the submitted values and preserve factor state

#### Scenario: Invalid proof without a live session
- **WHEN** an unauthenticated caller sends a well-formed document with invalid proof fields
- **THEN** return the authentication challenge without attempting a factor change

#### Scenario: Large proof request
- **WHEN** a large unrelated field accompanies an authenticator proof
- **THEN** evaluate the credential fields with the same rules as a compact request
