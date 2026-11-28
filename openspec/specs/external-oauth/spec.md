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

### Requirement: Redeem a CLI login code

The service SHALL accept a JSON code and verifier at POST /api/v1/auth/cli/exchange, subject to the CLI feature switch and login rate limit.

#### Scenario: Complete a CLI login

- **WHEN** an active account's current code is presented with its matching S256 verifier
- **THEN** issue one federated session, record a successful token grant and return access and refresh tokens, bearer type and access lifetime.

#### Scenario: Refuse credentials

- **WHEN** a code is unknown, expired, already used, presented with an incorrect verifier, or bound to an ineligible account
- **THEN** return HTTP 400 with the same invalid_grant response and record the refusal. A current code presented with an incorrect verifier or ineligible account is consumed.

#### Scenario: Concurrent redemption

- **WHEN** two callers redeem one valid code concurrently
- **THEN** at most one receives tokens and only one session is created.

#### Scenario: Validate input before redemption

- **WHEN** the submitted JSON lacks the required string fields, contains an empty code or exceeds either field's 128-character limit
- **THEN** respond with HTTP 400 and the invalid_grant error before claiming any code. An empty verifier on a valid code reaches the proof check and consumes the code.

#### Scenario: Session storage fails

- **WHEN** a valid exchange cannot persist its session
- **THEN** roll back the code claim so the CLI can retry.

### Requirement: Decode CLI exchange documents before selecting the feature response
The service SHALL accept UTF-8, UTF-16 and UTF-32 JSON exchange documents, including documents with padding beyond two MiB, and ignore unrelated fields.

#### Scenario: Exchange disabled
- **WHEN** a validly shaped exchange arrives while CLI login is disabled
- **THEN** return the disabled-login problem regardless of JSON encoding

#### Scenario: Unreadable request
- **WHEN** the submitted JSON bytes cannot be decoded as text
- **THEN** return the HTTP 400 body-parsing problem

#### Scenario: Malformed JSON or invalid fields
- **WHEN** the text is malformed JSON or the submitted fields fail exchange validation
- **THEN** return the HTTP 400 invalid_grant response

### Requirement: Decode provider HTTP responses
The service SHALL support identity, gzip and deflate content codings on both the token response and the subsequent user profile. Each decoded JSON document SHALL fit within one MiB.

#### Scenario: Provider uses different codings on consecutive requests
- **WHEN** the token endpoint returns gzip and the profile endpoint returns deflate
- **THEN** the service reads the token and processes the profile with the usual account mapping rules

#### Scenario: Decoded document exceeds the bound
- **WHEN** either decoded response exceeds one MiB
- **THEN** the provider exchange fails

### Requirement: Read provider JSON in Unicode encodings
The service SHALL accept UTF-8, UTF-16 and UTF-32 token and profile JSON documents, with or without a byte order mark and in either applicable byte order. The one MiB limit SHALL apply to the document bytes after HTTP decompression and before text conversion.

#### Scenario: Different text encodings during a single exchange
- **WHEN** a provider returns a UTF-16 token response followed by a UTF-32 profile
- **THEN** process both documents and preserve the Unicode subject

#### Scenario: Invalid encoding
- **WHEN** either document contains truncated Unicode code units
- **THEN** reject the exchange

### Requirement: Read raw deflate provider documents
The service SHALL accept raw DEFLATE and zlib-wrapped DEFLATE under the deflate content coding for remote OAuth token and profile JSON responses.

#### Scenario: Provider uses different deflate representations
- **WHEN** either endpoint returns raw deflate and the other returns a supported encoding
- **THEN** decode each document independently and apply the existing one MiB decoded size limit to each
