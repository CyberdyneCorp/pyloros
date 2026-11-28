## ADDED Requirements

### Requirement: Preserve billing ownership across account erasure
A committed account erasure SHALL remove its Stripe customer mapping and entitlements while preserving processed event IDs. A new account registered with the same email SHALL start without the erased account's access.

#### Scenario: A subscription update arrives after erasure
- **WHEN** a subscription update identifies only the former Stripe customer
- **THEN** defer it with the reason `unmapped customer`
- **AND** replaying an already processed checkout leaves the customer unmapped

#### Scenario: A checkout establishes a replacement mapping
- **WHEN** a fresh signed checkout maps the customer to the replacement account UUID and the deferred update is redelivered
- **THEN** apply the subscription plan to the replacement account and treat subsequent delivery of the same processed update as a replay

#### Scenario: PostgreSQL rejects the account deletion at commit
- **WHEN** the erasure transaction rolls back
- **THEN** the original customer mapping and entitlement remain available and a subsequent renewal applies to the original account
