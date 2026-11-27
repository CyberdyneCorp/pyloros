## ADDED Requirements

### Requirement: Claim a verified Play subscription
The service SHALL authenticate the caller and verify the purchase for the configured Android package before granting mapped product access.

#### Scenario: Claim a subscription
- **WHEN** Play confirms an eligible subscription line item matching the requested product
- **THEN** bind the token to the account and return the mapped entitlement and its expiry

#### Scenario: Repeat a claim
- **WHEN** two accounts present the same purchase token
- **THEN** at most one account may own it and the other receives a conflict

#### Scenario: Reject a mismatched product
- **WHEN** the purchased line items do not include the requested product
- **THEN** reject the purchase and preserve the entitlement ledger
