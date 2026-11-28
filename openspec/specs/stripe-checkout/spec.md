# stripe-checkout Specification

## Purpose
Define hosted checkout creation for signed-in users and server-managed Stripe customers.

## Requirements

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

### Requirement: Select an owned customer when multiple mappings exist
When multiple Stripe customer IDs belong to the authenticated account, hosted checkout SHALL supply one of those IDs and the account UUID as the client reference. Selection among the owned IDs is unspecified.

#### Scenario: Storage order changes
- **WHEN** PostgreSQL reorganizes the mapping table between checkout requests
- **THEN** either owned customer remains eligible and another account’s customer remains ineligible

#### Scenario: A hosted checkout is created after a repurchase
- **WHEN** two purchases under distinct customer IDs have granted the same account the same product and plan
- **THEN** creating the next hosted checkout leaves the existing grant and its latest purchase reference unchanged
