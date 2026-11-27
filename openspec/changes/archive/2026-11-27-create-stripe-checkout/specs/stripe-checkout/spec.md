## ADDED Requirements

### Requirement: Create a hosted checkout session
The service SHALL allow an authenticated user to request a hosted checkout session for an eligible product when Stripe billing is enabled.

#### Scenario: Start checkout
- **WHEN** a signed-in user selects a grantable product and a price
- **THEN** the provider request identifies the user, product and plan and the service returns the resulting session identifier and URL

#### Scenario: Reuse a mapped customer
- **WHEN** the user has a stored Stripe customer identifier
- **THEN** the service includes it in the provider request

#### Scenario: Decline an unavailable product
- **WHEN** the product is unknown or inactive
- **THEN** the service returns a validation error before creating a provider session
