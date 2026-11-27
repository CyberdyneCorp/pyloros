## ADDED Requirements

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
