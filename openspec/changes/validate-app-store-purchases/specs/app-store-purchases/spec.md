## ADDED Requirements
### Requirement: Claim a verified App Store transaction
The service SHALL authenticate the customer and validate the signed transaction against the configured application, environment and Apple trust roots before granting product access.
#### Scenario: Complete a purchase
- **WHEN** the authenticated customer supplies a valid transaction for a mapped product
- **THEN** bind its original transaction to the customer and return the mapped entitlement and expiry
#### Scenario: Handle competing owners
- **WHEN** another customer claims the same original transaction
- **THEN** reject the claim and preserve existing access
#### Scenario: Verification fails
- **WHEN** the signature, certificate status or application identity cannot be verified
- **THEN** preserve purchase ownership and access
#### Scenario: Replay an older purchase
- **WHEN** a receipt predates revocation of its entitlement or would shorten a later renewal
- **THEN** preserve the later access decision

#### Scenario: Certificate status service unavailable
- **WHEN** an online certificate check cannot obtain a status response
- **THEN** return a retryable failure and leave the purchase unclaimed
