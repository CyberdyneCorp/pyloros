## ADDED Requirements

### Requirement: Self-register a public client

An enabled issuer SHALL accept public OAuth client registrations subject to its redirect policy, grant restrictions, scope ceiling and registration quota.

#### Scenario: Register a client

- **WHEN** the submitted metadata is eligible
- **THEN** return the issued identifier and effective public metadata, persist an untrusted client and record the registration in the administrative audit log.

#### Scenario: Decline a request

- **WHEN** registration is disabled or the request exceeds its quota or violates metadata policy
- **THEN** return the applicable status and error, preserving the existing registrations.

#### Scenario: Continue on another issuer

- **WHEN** a newly registered client starts authorization on the other backend
- **THEN** enforce the same redirect, consent and token restrictions using the shared registration.
