# mfa-challenges Specification

## Purpose
Preserve the account and factor context of an in-progress login across backend transitions.

## Requirements

### Requirement: Portable second-factor credential
The service SHALL issue a signed MFA credential with the issuer, account, issue time, expiry and fresh challenge identifier. Password challenges SHALL carry no factor binding. Passkey challenges SHALL bind the passkey and ceremony together. Email-link challenges SHALL bind the pending link. Verification SHALL enforce the selected algorithm, signature, issuer, expiry, credential type and binding shape.

#### Scenario: Cross-backend continuation
- **WHEN** either deployment signs an unexpired challenge with the shared signing configuration
- **THEN** the other can recover its subject and factor binding

#### Scenario: Other token purpose
- **WHEN** an access or refresh credential is passed to the challenge verifier
- **THEN** verification fails

### Requirement: Periodic email confirmation on password login
The service SHALL require email confirmation when the policy interval is set and the account has never confirmed or the interval has elapsed. A required confirmation SHALL create a pending challenge with a random email link, a two-digit match code, and a separate browser polling credential bound to the challenge. The service SHALL store only the link digest.

#### Scenario: Recent confirmation
- **WHEN** a password login occurs before the next confirmation is due
- **THEN** the workflow continues without creating a challenge or sending email

#### Scenario: Delivery failure
- **WHEN** the mail transport cannot send a required confirmation
- **THEN** the workflow refuses login, rolls back the pending challenge, and records the delivery failure

### Requirement: Confirm sign-in by email
The configured mail provider SHALL deliver the match code, source address, device and browser confirmation URL to the account email address. The URL SHALL carry the one-time token in its fragment. SMTP submission SHALL verify the relay certificate and require encryption. The mock provider SHALL retain messages in a process-local outbox.

#### Scenario: SMTP unavailable
- **WHEN** the configured relay cannot securely accept the message
- **THEN** delivery returns a failure to the confirmation workflow

#### Scenario: Account base fallback
- **WHEN** no explicit account-links base is set
- **THEN** the email uses the origin of the configured OIDC login URL or post-login URL

### Requirement: Email recipient inspection and decision
The inspect, confirm and deny endpoints under /api/v1/auth/magic-link SHALL authenticate the submitted link token and share a per-source quota. Only a pending unexpired link SHALL reveal the match code, timestamps and originating device details. Inspection SHALL set Cache-Control to no-store and leave the challenge pending.

#### Scenario: Recipient decides
- **WHEN** the holder confirms or denies a pending link
- **THEN** exactly one decision succeeds, returns 204, and is recorded in the audit trail

#### Scenario: Used or expired link
- **WHEN** the supplied token has expired or already received a decision
- **THEN** inspection and decision return the invalid-link error without revealing the original challenge

### Requirement: Email challenge completion
The initiating browser SHALL present a signed MFA credential bound to the same user and email challenge. Pending and successful responses SHALL disable caching. Polls SHALL use a separate source quota.

#### Scenario: Awaiting approval
- **WHEN** a valid credential identifies an unexpired pending challenge
- **THEN** return 202 with pending status.

#### Scenario: Confirmed sign-in
- **WHEN** an active user’s approved challenge is consumed
- **THEN** issue the session once with both authentication methods and the confirmation time, set browser cookies and record the login.

#### Scenario: Refused completion
- **WHEN** the challenge expired, was denied, was consumed, or does not match the credential
- **THEN** refuse completion and record the failure.

### Requirement: Verify an enrolled login factor
The factor verifier SHALL accept existing encrypted enrollments for active users and consume the factor in the caller’s PostgreSQL transaction.

#### Scenario: Authenticator code
- **WHEN** a six-digit code matches the current thirty-second step or an adjacent step
- **THEN** accept it only if the matched step strictly advances the account’s last used step.

#### Scenario: Recovery code
- **WHEN** a submitted code matches an unused recovery record for that account
- **THEN** consume it once and report recovery authentication to the session issuer.

#### Scenario: Rollback
- **WHEN** session creation rolls back after accepting the factor
- **THEN** the factor remains available to a subsequent transaction.

### Requirement: Complete password-bound MFA
The verification endpoint SHALL require a signed password-bound MFA credential and a valid enrolled factor before creating a session. The service SHALL audit unsuccessful checks and apply a per-source quota to validated requests.

#### Scenario: Complete password login
- **WHEN** the client presents a valid authenticator or recovery code
- **THEN** commit the factor claim, authenticated session and successful MFA audit together and return first-party tokens and cookies.

#### Scenario: Invalid factor or challenge
- **WHEN** the submitted factor or credential fails verification
- **THEN** return the corresponding authentication error without issuing credentials.

### Requirement: Read authenticator enrollment
The MFA status endpoint SHALL report whether the authenticated first-party account has an enabled authenticator and how many unused recovery codes remain.

#### Scenario: Enrolled account
- **WHEN** a first-party caller reads its enrollment
- **THEN** return its enrollment flag and count only its own unused codes.

#### Scenario: Disabled authenticator
- **WHEN** the authenticator is disabled or setup is pending
- **THEN** return a disabled status and zero remaining codes.

#### Scenario: OAuth access
- **WHEN** the credential belongs to an OAuth client
- **THEN** refuse access to the enrollment status.
