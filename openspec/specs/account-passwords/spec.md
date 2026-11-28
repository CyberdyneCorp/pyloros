# account-passwords Specification

## Purpose
Verify stored account credentials before deciding whether sign-in requires a second factor or a new session.

## Requirements

### Requirement: Verify existing account passwords
The password verifier SHALL support Argon2 and bcrypt under explicit scheme selection, using Argon2 by default. Missing credentials SHALL incur a synthetic check for the selected scheme and always fail. Account and OAuth credential verification SHALL share a process-wide concurrency limit.

#### Scenario: Existing credential
- **WHEN** the supplied password matches a valid stored hash in the selected scheme
- **THEN** password verification succeeds

#### Scenario: Invalid credential
- **WHEN** the stored credential is absent, malformed, or belongs to a different scheme
- **THEN** password verification fails

### Requirement: Database-backed password login decision
The credential step SHALL return the same invalid-credentials decision for unknown accounts, absent passwords and mismatches while recording distinct audit reasons. It SHALL refuse inactive accounts after verifying the password. It SHALL check the current credential and enrollment before advancing a successful attempt.

#### Scenario: Enrolled account
- **WHEN** a valid password belongs to an active TOTP-enrolled account
- **THEN** the service records a successful MFA challenge and returns a short-lived challenge without creating a session

#### Scenario: Additional login policy
- **WHEN** a valid password belongs to an active account without TOTP
- **THEN** the caller can continue the login transaction to evaluate further authentication requirements

### Requirement: Password attempt throttling
The login admission check SHALL charge each validated password attempt against a process-local source IP quota before looking up the account. Unresolved IPs SHALL share a quota. A positive limit SHALL allow that many immediate attempts and replenish evenly over one minute. A nonpositive limit SHALL disable throttling.

#### Scenario: Quota exhausted
- **WHEN** a caller has less than one attempt available
- **THEN** the check returns HTTP 429 with Retry-After of 60 seconds and records a rate-limited login failure for the attempted email

#### Scenario: Concurrent attempts
- **WHEN** simultaneous requests arrive for the same IP
- **THEN** each accepted attempt consumes a separate unit of available quota

### Requirement: Password login over HTTP
POST /api/v1/auth/login SHALL validate email and password, throttle by source and evaluate the first-party login policies. A completed login SHALL commit its session and logon audit together, then return the bearer token pair and the three session cookies. A challenged login SHALL return its method and pending credential without setting session cookies.

#### Scenario: Password login completes
- **WHEN** the account is active, the password matches and no second factor is due
- **THEN** the browser can immediately use the returned access cookie to read its current profile

#### Scenario: Required second factor
- **WHEN** TOTP or email confirmation is required
- **THEN** the response identifies the required method and holds the session until completion

#### Scenario: Stale access cookie
- **WHEN** password credentials are submitted with an existing access cookie
- **THEN** the handler authenticates the submitted credentials independently of the old session

### Requirement: Authenticated password change

A first-party account SHALL be able to change its password by supplying its current password and a replacement that satisfies the password policy.

#### Scenario: Successful change
- **WHEN** both passwords pass their respective checks
- **THEN** persist a salted replacement hash readable by both deployments, revoke all active sessions including the caller, update the access-token cutoff, audit the number of sessions revoked and return an empty 204 response.

#### Scenario: Incorrect current password
- **WHEN** the current password fails verification or the account lacks a stored password
- **THEN** return the same 401 error and record the reason without changing credentials or sessions.

#### Scenario: Concurrent change
- **WHEN** competing changes supply the same old password
- **THEN** only a caller whose proof still matches the locked account may commit.

### Requirement: Email password recovery
The service SHALL accept an email address for password recovery and allow the owner to redeem a valid emailed credential once.

#### Scenario: Request recovery
- **WHEN** an admitted caller submits a valid address
- **THEN** return the same empty success response for known and unknown accounts and deliver a time-limited credential only to the registered address.

#### Scenario: Redeem the credential
- **WHEN** the owner submits an unused, unexpired credential and a valid replacement password
- **THEN** replace the password, verify the email, assign an eligible domain organization to an unaffiliated account, invalidate existing sessions, consume the credential and record the successful outcome.

#### Scenario: Invalid credential
- **WHEN** a credential is unknown, expired or already consumed
- **THEN** reject the reset without altering the account and record the refusal.

#### Scenario: Concurrent redemption
- **WHEN** two callers redeem the same credential simultaneously
- **THEN** at most one password replacement commits.

#### Scenario: Browser retains a stale session cookie
- **WHEN** a browser requests or confirms a reset with an old access cookie
- **THEN** evaluate the reset request independently of that cookie.

#### Scenario: Two outstanding recovery links
- **WHEN** the same account receives two distinct links and redeems them sequentially before expiry
- **THEN** each successful reset consumes its submitted credential and records one success
- **AND** either issuance order permits the second reset, after which the account authenticates with the last committed password

### Requirement: Decode email verification requests

The service SHALL accept a JSON object containing a string token in UTF-8, UTF-16 or UTF-32 and SHALL retain the submitted value in field validation errors.

#### Scenario: Token is an object

- **WHEN** a client supplies a nested object as the verification token
- **THEN** return a field validation error containing the original object and its integer values before opening the redemption transaction.

#### Scenario: Additional fields

- **WHEN** a client supplies a string token with unrelated JSON fields
- **THEN** ignore the unrelated fields when validating the token and continue to redemption.

### Requirement: Validate password recovery documents

The service SHALL decode UTF-8, UTF-16 and UTF-32 JSON on both password recovery routes. It SHALL report each invalid field with the submitted value and each missing field with the containing object.

#### Scenario: Multiple invalid confirmation fields

- **WHEN** a client supplies a token of the wrong type and omits the replacement password
- **THEN** return both field errors in schema order and preserve the exact integer values in each error's input.

#### Scenario: Additional fields in recovery requests

- **WHEN** a client requests recovery using a JSON object with an email and unrelated fields
- **THEN** validate the email independently of the unrelated fields before applying the recovery quota.

### Requirement: Normalize internationalized account email

The service SHALL normalize the local part of an accepted account address to NFC and use the lowercase Unicode form of its internationalized domain before account lookup and creation.

#### Scenario: Recovery with an equivalent domain spelling

- **WHEN** a client submits the ASCII IDNA spelling of a registered internationalized domain
- **THEN** issue recovery for the same stored account as a request using the Unicode spelling.

#### Scenario: Decomposed local part

- **WHEN** a client submits an accepted local part with canonically decomposed characters
- **THEN** use its canonically composed spelling while preserving local-part case.

### Requirement: Validate account email domains

The service SHALL reject address literals, reserved public suffixes, invalid ASCII domain characters, and domains exceeding DNS size limits. The service SHALL evaluate an internationalized domain using its encoded DNS spelling.

#### Scenario: Invalid characters in a domain

- **WHEN** the domain contains several disallowed ASCII punctuation characters
- **THEN** report a field validation error identifying the distinct invalid characters in sorted order.

#### Scenario: Label exceeds its DNS length

- **WHEN** a client submits an ASCII domain label longer than 63 characters
- **THEN** identify the length excess before account lookup.

#### Scenario: Numeric end of an ASCII suffix

- **WHEN** the top-level domain ends in an ASCII digit and is not an internationalized label
- **THEN** reject the address before the recovery quota is spent.

### Requirement: Validate and deliver account mailboxes

The service SHALL accept an unquoted local part longer than 64 bytes when the complete address remains within the 254-byte limit and satisfies account address syntax. Account mail delivery SHALL support these validated recipients. Validation SHALL reject unsafe Unicode, invalid ASCII and quoted local parts.

#### Scenario: Register and verify a long mailbox

- **WHEN** a valid long address is submitted for registration and the configured relay accepts its verification email
- **THEN** persist the account and allow the emailed credential to be redeemed.

#### Scenario: Disallowed characters before the domain

- **WHEN** a submitted local part includes a disallowed control or formatting character
- **THEN** report a validation error before consuming an allowance or sending mail.

### Requirement: Preserve password authentication time under contention

A password-only login SHALL retain the successful credential check time for its session credentials while waiting to recheck the account.

#### Scenario: Account-wide logout overlaps password verification

- **WHEN** a valid password is checked before the logout cutoff and the account lock delays session creation
- **THEN** the access token retains its original issue time and is refused when revocation is enforced

#### Scenario: Password is verified after the cutoff

- **WHEN** a single-step password login verifies in a later whole second than the account cutoff and creates a live session
- **THEN** the resulting access credential passes the account cutoff check

### Requirement: Preserve numeric input behavior for email verification and password recovery
Requests for email verification and password recovery SHALL accept Unicode JSON, validate the scalar fields used by the operation and ignore unrelated values after document decoding.

#### Scenario: Unused numeric input
- **WHEN** a valid credential is accompanied by a non-finite value in an unused field
- **THEN** proceed with normal credential handling

#### Scenario: Unrepresentable validation error
- **WHEN** a validation error would include a non-finite number in its JSON response
- **THEN** return the unhandled server error response

### Requirement: Decode password change requests before validating credentials
The password change handler SHALL decode Unicode JSON documents before authenticating the caller and validate the current and new password fields after checking the session. Unknown properties SHALL be ignored in otherwise valid requests, including documents larger than two MiB.

#### Scenario: Unauthenticated caller with valid JSON
- **WHEN** a caller without a session submits a syntactically valid document with invalid field types
- **THEN** return the authentication challenge

#### Scenario: Wide encoded password change
- **WHEN** an authenticated caller supplies both valid password fields in UTF-16 or UTF-32 JSON
- **THEN** change the credential and apply the existing session revocation policy

### Requirement: Decode Unicode registration documents
The public account registration endpoint SHALL accept UTF-8, UTF-16 and UTF-32 JSON and validate the submitted email and password, including when ignored fields make the document larger than two MiB.

#### Scenario: Wide document with unknown properties
- **WHEN** an available address and valid password are submitted in UTF-32 JSON with additional fields
- **THEN** create the account and issue its verification email through the configured delivery provider

#### Scenario: Incorrect field type
- **WHEN** a registration document supplies a finite numeric email
- **THEN** include the original number in the field validation response

### Requirement: Read historical Argon2 credentials
The verifier SHALL interpret an omitted version field in a stored Argon2 credential as version 16 for both account passwords and OAuth client secrets.

#### Scenario: Historical version omitted
- **WHEN** a correct secret is submitted for an Argon2i, Argon2d or Argon2id version 16 hash with no version field
- **THEN** verification succeeds

#### Scenario: Version explicitly recorded
- **WHEN** the stored hash specifies a version
- **THEN** verification uses that version and rejects a digest that does not match it

### Requirement: Register a password account
The service SHALL register an unverified account with a normalized email address, a password hash and an independently generated managed wallet.

#### Scenario: New account
- **WHEN** a validated, admitted registration supplies an unused email address
- **THEN** return the new account identifier, normalized email, uncompressed public key and checksummed wallet address, and email a single-use verification code.

#### Scenario: Wallet coexistence
- **WHEN** either deployment reads a newly registered account with the same master key
- **THEN** its decrypted 32-byte private key derives the stored public key and wallet address.

#### Scenario: Existing account
- **WHEN** registration encounters an email already registered, including through a concurrent request
- **THEN** return a conflict and preserve the existing account.

#### Scenario: Registration integrations
- **WHEN** a registration has matching webhook subscriptions and hooks
- **THEN** commit pending webhook deliveries with the account and dispatch hooks after commit.

#### Scenario: Registration while hook migration is incomplete
- **WHEN** the Rust service receives a new registration with an active registration hook lacking a component binding
- **THEN** return HTTP 503 before sending verification email and roll back the new account and pending hook deliveries.

#### Scenario: Verify a registration after switching backends
- **WHEN** a registration succeeds with multiple matching hooks and its email verification code is presented to the other backend
- **THEN** verify the same account, allow sign-in there, and execute each registration hook once for the account.
- **AND** a duplicate registration returns a conflict without sending another verification email or dispatching more registration hooks.

### Requirement: Count stored account password schemes
An operator SHALL be able to obtain aggregate counts of all accounts by stored password prefix in one read-only database snapshot. The report SHALL include Argon2, bcrypt, absent credentials and unrecognized values, with zero counts for empty categories. It SHALL return only these counts.

#### Scenario: Historical accounts coexist with migrated accounts
- **WHEN** the account table contains Argon2i, Argon2d, Argon2id, original bcrypt or bcrypt 2a, 2b or 2y prefixes
- **THEN** count each recognized prefix in its corresponding family
- **AND** count SQL NULL as absent and other values, including the empty string, as unrecognized

#### Scenario: Account completes recovery
- **WHEN** a bcrypt account receives a replacement Argon2 credential and the transaction commits
- **THEN** a subsequent report counts the account only under Argon2

### Requirement: Preserve MFA enrollment during operator password recovery
An operator password reset that migrates a bcrypt credential to Argon2 SHALL preserve the account's authenticator enrollment, last accepted authenticator step and recovery-code usage.

#### Scenario: Recover an enrolled account with partially used recovery codes
- **WHEN** an operator replaces the password on an Argon2-configured writer
- **THEN** used recovery codes remain spent and unused recovery codes remain available
- **AND** the previous session's refresh credential is refused

#### Scenario: Sign in after the reset
- **WHEN** the user submits the replacement password after the revocation cutoff on a compatible peer
- **THEN** the peer requires the enrolled second factor
- **AND** the other backend can complete that challenge with the existing authenticator and issue a session usable by the peer

### Requirement: Bcrypt recovery cohort inventory
Operators SHALL be able to request a read-only inventory of bcrypt-prefixed accounts grouped by active status and presence of a nonblank primary email. The report SHALL return four counts including zeroes and use the same bcrypt prefix classification as the default family inventory.

#### Scenario: Missing primary email
- **WHEN** an active bcrypt account has a null, empty or whitespace-only primary email
- **THEN** it contributes to the active count without email

#### Scenario: Password scheme changes
- **WHEN** a bcrypt credential is replaced with Argon2
- **THEN** reports from other connections exclude that account from its previous cohort only after commit

### Requirement: Confirm email verification only after commit
The service SHALL return HTTP 500 when PostgreSQL explicitly rejects a valid email confirmation at commit. The code consumption, account verification, domain membership changes and success audit SHALL roll back together.

#### Scenario: Retry an emailed code after rollback
- **WHEN** a valid, unexpired code is retried after the rejected transaction and the database accepts the new transaction
- **THEN** return HTTP 204, consume the code, verify the account, apply any eligible domain membership and record one successful verification
- **AND** a later replay returns HTTP 400.

### Requirement: Commit each recovery email request independently
For an eligible address, the service SHALL issue a distinct recovery credential for each admitted request and record the successful request in the same transaction.

#### Scenario: Two writers issue recovery email concurrently
- **WHEN** two writers accept overlapping requests for the same address and both transactions commit
- **THEN** the recipient receives two distinct credentials, each matching a stored unused token for that account

#### Scenario: SMTP refuses the recipient
- **WHEN** the relay refuses a known recipient during submission
- **THEN** return HTTP 500 and roll back the recovery credential and successful request audit

#### Scenario: Commit rejected after delivery
- **WHEN** the relay accepts the email and PostgreSQL explicitly rejects the request at commit
- **THEN** return HTTP 500, preserve the previous credential and audit state, and reject the discarded link on redemption

### Requirement: Verify the shipped password provider
The release executable SHALL provide an offline check of the configured account password scheme using synthetic credentials.

#### Scenario: Check a configured provider
- **WHEN** an operator invokes the provider check
- **THEN** exercise current hash creation and verification, a historical hash, wrong-password refusal and missing-account refusal; report the scheme and outcomes without disclosing credentials or hashes

#### Scenario: Unusable provider configuration
- **WHEN** the configured scheme is unsupported or a check fails
- **THEN** exit unsuccessfully
