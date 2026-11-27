# passkey-login Specification

## Purpose
Define discoverable passkey sign-in and preserve pending authentication across a backend switch.

## Requirements

### Requirement: Sign in with a discoverable credential

The service SHALL support account-independent initiation and verify a user-present, user-verified assertion against the registered credential before authenticating its owner.

#### Scenario: Begin sign-in

- **WHEN** an approved browser or native client requests sign-in options with passkeys enabled
- **THEN** return a fresh challenge with required user verification and the configured relying party and timeout. Persist an expiring challenge bound to the origin, client and current policy. Omit account identifiers and credential lists.

#### Scenario: Complete sign-in on either backend

- **WHEN** a client presents the matching binding and an eligible signed assertion for an unconsumed challenge
- **THEN** consume the challenge once, validate the owner, handle and credential state, update its usage, and issue the applicable session or MFA challenge with its audit event.

#### Scenario: Evaluate the authenticator counter

- **WHEN** a valid assertion arrives for a device-bound credential with positive stored and returned counters
- **THEN** require the returned value to exceed the stored value. Allow a zero counter or a non-increasing counter on a backup-eligible credential, and preserve the greatest observed value.

#### Scenario: Complete a passkey-bound second factor

- **WHEN** the same client submits the MFA challenge with its original origin and binding
- **THEN** consume that challenge once, recheck the credential is active, and issue a session only after a valid authenticator or unused recovery code. A wrong binding preserves the challenge. A wrong factor code consumes it.
