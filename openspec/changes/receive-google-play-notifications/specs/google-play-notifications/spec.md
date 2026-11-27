## ADDED Requirements

### Requirement: Reconcile authenticated Play notifications
The service SHALL accept Google-authenticated notifications for its configured Android application and update the known purchase owner's access using current store data.

#### Scenario: Receive a renewal
- **WHEN** Google confirms a renewed subscription for a known purchase
- **THEN** update the mapped grant through the confirmed expiry and record the message as processed

#### Scenario: Reject an unexpected sender
- **WHEN** the sender, audience, signature, or application fails validation
- **THEN** reject the delivery and preserve purchase and entitlement state

#### Scenario: Handle redelivery
- **WHEN** a previously processed message is delivered again
- **THEN** acknowledge the delivery without applying another entitlement change

#### Scenario: Store unavailable
- **WHEN** the purchase state cannot be retrieved due to a transient provider failure
- **THEN** leave the message available for retry and preserve access
