## Purpose
Preserve the account and factor context of an in-progress login across backend transitions.

## ADDED Requirements

### Requirement: Portable second-factor credential
The service SHALL issue a signed MFA credential with the issuer, account, issue time, expiry and fresh challenge identifier. Password challenges SHALL carry no factor binding. Passkey challenges SHALL bind the passkey and ceremony together. Email-link challenges SHALL bind the pending link. Verification SHALL enforce the selected algorithm, signature, issuer, expiry, credential type and binding shape.

#### Scenario: Cross-backend continuation
- **WHEN** either deployment signs an unexpired challenge with the shared signing configuration
- **THEN** the other can recover its subject and factor binding

#### Scenario: Other token purpose
- **WHEN** an access or refresh credential is passed to the challenge verifier
- **THEN** verification fails
