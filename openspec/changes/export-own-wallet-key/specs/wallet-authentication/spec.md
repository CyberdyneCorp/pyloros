## ADDED Requirements

### Requirement: Optional custodial wallet export
Pyloros SHALL authenticate GET /api/v1/users/me/private-key using the account holder's first-party session. Export SHALL default to disabled and be configurable through EXPOSE_PRIVATE_KEY_ENDPOINT.

#### Scenario: Export is disabled
- **WHEN** an authenticated account requests its wallet key on a default deployment
- **THEN** the service returns HTTP 404

#### Scenario: Account has a custodial wallet
- **WHEN** export is enabled and the authenticated account has a decryptable key and an address
- **THEN** the response contains the account ID, stored address and a lowercase hex key prefixed with 0x

#### Scenario: Account has no custodial wallet
- **WHEN** either the encrypted key or its address is absent
- **THEN** the enabled endpoint returns HTTP 404

#### Scenario: Account exhausts its quota
- **WHEN** the account has consumed the available five requests per minute
- **THEN** subsequent requests receive HTTP 429 with a Retry-After header

#### Scenario: Deployment has no configured decryption key
- **WHEN** export is enabled, the account has wallet material and MASTER_KEY is absent
- **THEN** Pyloros returns HTTP 503

#### Scenario: Replica uses a different explicit encryption key

- **WHEN** an authenticated account exports a managed wallet through a replica configured with a different encryption key from the writer
- **THEN** return HTTP 500 and preserve the stored wallet. The same session can still export through a correctly keyed replica and recover the private key corresponding to the original address.
