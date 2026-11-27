# external-oauth Specification

## Purpose
Define how clients initiate external identity-provider sign-in and preserve return instructions across deployments.

## Requirements

### Requirement: Initiate external sign-in

The service SHALL start sign-in for enabled external providers and return either a JSON authorization URL and state or an HTTP redirect to that URL.

#### Scenario: Persist return instructions

- **WHEN** a client starts a supported provider flow
- **THEN** create expiring, unused PostgreSQL state binding the provider and return mode so either backend can receive the callback.

#### Scenario: Validate the destination

- **WHEN** a client requests fragment delivery or supplies a frontend destination
- **THEN** require the destination to match a permitted URL. Fragment delivery requires an explicit destination.

#### Scenario: Start CLI sign-in

- **WHEN** CLI login is enabled and the client requests CLI delivery
- **THEN** require a permitted loopback port and an S256 challenge, reject a frontend destination and bind the exchange parameters to the state.

#### Scenario: Preserve a legacy CLI challenge

- **WHEN** the submitted S256 challenge has a single trailing line feed
- **THEN** accept initiation and persist the entire submitted string for the CLI exchange.

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

#### Scenario: Reclaim an unverified account

- **WHEN** the provider verifies an address already held by an unverified local account
- **THEN** link the identity to that account, verify the address, apply domain membership, clear the prior password and enrolled second factor, invalidate recovery codes and revoke existing sessions in the callback transaction.

#### Scenario: Recognize a returning subject

- **WHEN** a linked provider subject returns with a changed email address
- **THEN** retain its local account and managed wallet. Update an available provider avatar and refuse sign-in if the account is inactive.
