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

#### Scenario: Repeat a claim with a grant hook
- **WHEN** the same account successfully submits a verified purchase twice with one active bound entitlement grant hook
- **THEN** retain one purchase owner and one active entitlement and dispatch the grant hook once for each successful submission

#### Scenario: Claim while a grant hook lacks a binding
- **WHEN** an otherwise eligible purchase requires an active grant hook whose component binding is missing
- **THEN** respond with HTTP 503 and roll back ownership, entitlement and hook delivery so the same claim can be resubmitted after binding
