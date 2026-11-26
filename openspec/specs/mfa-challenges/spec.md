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
