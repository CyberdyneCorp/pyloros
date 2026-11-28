# passkey-management Specification

## Purpose
Let signed-in users list, rename and revoke their own passkeys while preserving a way to sign in.

## Requirements

### Requirement: Manage the account's active passkeys
The service SHALL restrict inventory operations to a first-party credential with a live session owned by the active account.

#### Scenario: List enrolled passkeys
- **WHEN** the feature is enabled and an eligible account requests its inventory
- **THEN** return active credentials for the configured relying party ordered by creation time, including only the record ID, name, timestamps and backup flags, with caching disabled.

#### Scenario: Manage an enrolled credential
- **WHEN** the account renames or revokes a credential
- **THEN** restrict the change to an active credential for that account and relying party. Revocation requires recent authentication and an alternative sign-in method.

#### Scenario: Rename an active credential
- **WHEN** an eligible account submits a name of one to 64 characters that contains visible text after trimming whitespace
- **THEN** save the trimmed display name and return the updated metadata. Return HTTP 404 for a missing, revoked, foreign-account or other relying-party credential.

#### Scenario: Simultaneous removal of the last credentials
- **WHEN** two requests try to revoke the only remaining sign-in credentials for one account
- **THEN** serialize recovery checks so at least one method remains, and commit a successful revocation and its audit record together.

### Requirement: Decode Unicode JSON for passkey enrollment and reauthentication
The service SHALL decode supported UTF-8, UTF-16 and UTF-32 verification documents within the existing request byte limit.

#### Scenario: Encoded verification request
- **WHEN** a caller submits a validly encoded proof
- **THEN** apply the ordinary ceremony, binding and signature checks

#### Scenario: Invalid text
- **WHEN** a JSON body cannot be decoded as Unicode
- **THEN** return the HTTP 400 body-parsing problem

### Requirement: Dispatch overlapping passkey paths by method
The service SHALL serve capability discovery on GET and handle PATCH and DELETE on that same path using the credential identifier rules.

#### Scenario: Attempt a credential edit at the discovery path
- **WHEN** a caller sends PATCH or DELETE to the capabilities URL
- **THEN** process the request with capabilities as the submitted credential identifier, including ordinary authentication and validation

### Requirement: Enforce the passkey request size limit across chunks
The service SHALL enforce a limit of 65,536 body bytes before dispatching a passkey request, for both fixed-length and chunked uploads.

#### Scenario: Body ends at the limit
- **WHEN** the client finishes sending exactly 65,536 bytes
- **THEN** pass the complete body to the route for normal processing

#### Scenario: Final chunk crosses the limit
- **WHEN** the cumulative body size reaches 65,537 bytes
- **THEN** return HTTP 413 with the JSON detail "Passkey request too large" before invoking the route

### Requirement: Inventory authenticator models before migration
The operator tooling SHALL report counts of unrevoked credentials grouped by stored AAGUID and credential algorithm in a read-only transaction.

#### Scenario: Inventory an existing deployment
- **WHEN** credentials share a model identifier and algorithm
- **THEN** return their aggregate count, excluding revoked credentials, with missing identifiers represented as null

#### Scenario: No active credentials
- **WHEN** all credentials are revoked or the table is empty
- **THEN** return an empty JSON array

### Requirement: Apply login options quota after passkey request admission
The login options endpoint SHALL preserve the caller's quota on allowed CORS preflight requests and oversized uploads. Neither request SHALL create a ceremony.

#### Scenario: One login request remains
- **GIVEN** the caller has one login options request left in the current rate-limit window
- **WHEN** an allowed preflight and a 65,537-byte upload precede a valid 65,536-byte login options request
- **THEN** the valid request succeeds and returns the challenge for exactly one newly stored login ceremony

#### Scenario: Login quota is exhausted
- **GIVEN** the caller has exhausted the current login options allowance
- **WHEN** the caller submits a 65,537-byte upload followed by a valid small request within that window
- **THEN** the uploads receive HTTP 413 and HTTP 429 respectively, neither creates a ceremony, and an allowed preflight still succeeds

### Requirement: Report a rejected passkey rename
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects a passkey rename at commit.

#### Scenario: Retry a rename after rollback
- **WHEN** PostgreSQL rejects the rename transaction at commit
- **THEN** account and administrator inventories continue to show the original name, and a later successful rename returns the committed metadata

### Requirement: Issue options only for committed passkey ceremonies
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects a login, registration or reauthentication ceremony at commit.

#### Scenario: Challenge storage rolls back
- **WHEN** a browser or native client requests options and the ceremony transaction is rejected at commit
- **THEN** return the error without a ceremony identifier, public-key options, binding cookie or native binding secret

#### Scenario: Issue options after recovery
- **WHEN** the client retries after the database accepts writes
- **THEN** return the challenge and binding for the newly committed ceremony

### Requirement: Report explicit rejection of a passkey revocation
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects a passkey revocation at commit.

#### Scenario: Retry revocation after rollback
- **WHEN** a revocation fails at commit and the caller later retries after the failure clears
- **THEN** the credential stays active until the retry commits, and the credential activity history records one successful revocation

### Requirement: Recover from discarded passkey verification results
After a successful ceremony claim, the service SHALL return HTTP 500 when PostgreSQL explicitly rejects the transaction that stores an enrollment or reauthentication result.

#### Scenario: Rejected enrollment
- **WHEN** a valid enrollment proof consumes its ceremony and the credential transaction rolls back
- **THEN** the credential and enrollment activity are absent, the claimed ceremony remains consumed, and the caller can enroll with a fresh challenge

#### Scenario: Rejected reauthentication
- **WHEN** the transaction saving verified reauthentication rolls back after the ceremony claim
- **THEN** the previously committed credential counter, last-use time and session proof remain intact, and reauthentication requires a fresh ceremony
