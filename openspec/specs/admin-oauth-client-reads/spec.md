# admin-oauth-client-reads Specification

## Purpose
Let authorized operators inspect shared OAuth client registrations through the administrative REST API.

## Requirements

### Requirement: Inspect registered OAuth clients

The issuer SHALL allow an authorized administrator to inspect registered clients through the existing collection and detail endpoints, preserving filter, pagination and response semantics.

#### Scenario: Inspect shared registrations

- **WHEN** an authorized administrator requests a page of clients or a client by its identifier
- **THEN** the service returns the effective client metadata from the shared store, preserving optional fields and excluding credential material.

#### Scenario: Change operator access

- **WHEN** the caller loses administrative access or the administrative API is disabled
- **THEN** subsequent requests enforce the current access policy before returning client data.

#### Scenario: Request an invalid page or missing client

- **WHEN** an authorized caller supplies invalid pagination or requests an unknown identifier
- **THEN** the status and error fields match the existing client contract.

### Requirement: Operator permission inventory
The service SHALL let administrators list an active client's registered permissions in key order, including each description and creation time.

#### Scenario: An active client has no permissions
- **WHEN** an administrator requests its catalog
- **THEN** the response identifies the client and returns an empty list

#### Scenario: Inactive or missing client
- **WHEN** an administrator requests an unavailable client's catalog
- **THEN** the service returns a missing-client error

#### Scenario: Caller lacks administrator access
- **WHEN** the caller requests a catalog without operator privileges
- **THEN** the service refuses access before disclosing the client state
