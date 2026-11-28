## ADDED Requirements

### Requirement: Emit the registration webhook for federated account creation
With webhooks enabled and an active registration subscription, the callback SHALL enqueue one `user.registered` event when it creates an account. The event SHALL identify the created user. Linking a verified existing account, signing in again with the same provider identity, and replaying consumed state SHALL produce zero additional registration events.

#### Scenario: First sign-in followed by a returning sign-in
- **WHEN** the first callback creates an account and a subsequent sign-in resolves the same provider subject
- **THEN** both sessions identify the same user and the webhook ledger contains one registration event for that user

#### Scenario: Verified account already exists
- **WHEN** the callback links the provider identity to an existing verified account
- **THEN** issue the session for that account and omit the registration event

#### Scenario: Consumed state reaches a peer
- **WHEN** a callback reaches another backend after its state was consumed
- **THEN** reject the replay with HTTP 400 and preserve the registration event count
