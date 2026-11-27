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
