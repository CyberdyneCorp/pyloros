## ADDED Requirements

### Requirement: Maintain OAuth client registrations

The issuer SHALL allow an authorized operator to create, update, rotate the secret of and deactivate a client using the existing administrative REST contract.

#### Scenario: Provision an application

- **WHEN** an operator submits a valid registration
- **THEN** return the client metadata and newly issued credential, persist the credential hash and record the operator action without secret material.

#### Scenario: Edit a registration

- **WHEN** an operator changes a subset of fields
- **THEN** apply the accepted changes, preserve omitted fields, and record which fields were submitted.

#### Scenario: Roll a credential across backends

- **WHEN** an operator rotates a secret
- **THEN** return the replacement once and enforce the configured grace period for the previous credential on both services.

#### Scenario: Deactivate an application

- **WHEN** an operator deactivates a known client
- **THEN** retain the registration and audit history and enforce its inactive status on subsequent credential use.

#### Scenario: A deactivation is retried

- **WHEN** an operator repeats a successful deactivation
- **THEN** return an empty success response, keep the client inactive and record the operator action in the same audit chain.

#### Scenario: The audit write fails

- **WHEN** the service cannot record a deactivation in the administrative audit chain
- **THEN** the request fails and the client retains its previous active state.
