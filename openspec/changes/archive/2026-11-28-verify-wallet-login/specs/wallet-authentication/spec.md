## ADDED Requirements

### Requirement: Verify wallet sign-in

The service SHALL accept a challenge identifier and a personal-message signature, recover the signer from the stored message, and compare it to the challenge wallet. It SHALL enforce a verification quota and allow at most one successful login per challenge.

#### Scenario: First login

- **WHEN** a valid pending challenge authenticates a previously unknown wallet
- **THEN** create a wallet account and identity, issue a first-party session, record the login and mark the challenge completed
- **AND** return the wallet address, creation indicator, tokens and session cookies

#### Scenario: Returning wallet

- **WHEN** an active account already owns the authenticated wallet
- **THEN** issue the session for that account with its current authorization claims

#### Scenario: Rejected login

- **WHEN** the challenge is missing, expired, previously consumed, signed by a different wallet or linked to an inactive account
- **THEN** refuse the login, retain the prior challenge state and record the reason

#### Scenario: PostgreSQL rejects the login at commit

- **WHEN** the wallet proof is valid and PostgreSQL explicitly rejects the transaction at commit
- **THEN** return HTTP 500 without tokens or session cookies and leave the challenge pending
- **AND** either replica can accept the same proof while the challenge remains valid and issue one session
