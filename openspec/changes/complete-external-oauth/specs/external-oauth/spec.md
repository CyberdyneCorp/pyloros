## ADDED Requirements

### Requirement: Complete external sign-in

The service SHALL accept a provider response for an eligible state created on either backend and preserve the chosen return mode.

#### Scenario: Verify the callback

- **WHEN** a callback arrives
- **THEN** require an enabled provider and matching unused, unexpired state. Recheck any bound frontend destination against the current policy. Successful completion SHALL consume the state once.

#### Scenario: Resolve the external identity

- **WHEN** the provider returns a profile for a valid code
- **THEN** resolve the provider subject and apply the provider's email verification policy before linking or creating an account. Refuse inactive accounts and conflicting unverified email claims.

#### Scenario: Deliver the login result

- **WHEN** an eligible identity completes a browser flow
- **THEN** issue the session and record the authentication event, delivering the result using the bound cookie or fragment mode.

- **WHEN** the return mode is CLI
- **THEN** issue a short-lived code bound to the stored S256 challenge and return it to the selected loopback port. Create the session only after the CLI redeems that code.
