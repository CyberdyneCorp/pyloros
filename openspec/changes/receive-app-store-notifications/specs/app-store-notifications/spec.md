## ADDED Requirements
### Requirement: Process verified App Store notifications
The service SHALL authenticate App Store Server Notifications V2 and apply the verified change to the owner of the original purchase.
#### Scenario: Subscription enters grace
- **WHEN** a verified renewal record gives a later expiry during billing retry
- **THEN** keep the owner's mapped entitlement active through that expiry
#### Scenario: Refund a purchase
- **WHEN** Apple confirms a refund for a known purchase
- **THEN** revoke the corresponding App Store access and record the delivery atomically
#### Scenario: Process a redelivery
- **WHEN** a processed notification UUID arrives again
- **THEN** acknowledge the message without repeating the effect
#### Scenario: Unclaimed purchase
- **WHEN** the transaction is verified but has no owner
- **THEN** record the notification as deferred and reconsider it on redelivery
#### Scenario: Unverified identity
- **WHEN** a signature or required identity binding fails
- **THEN** reject the delivery and preserve existing access
