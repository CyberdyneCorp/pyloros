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
- **THEN** acknowledge the delivery without applying another entitlement change or dispatching another entitlement hook, including when the other backend processed the original message

#### Scenario: Store unavailable
- **WHEN** the purchase state cannot be retrieved due to a transient provider failure
- **THEN** leave the message available for retry and preserve access

#### Scenario: Match a multibyte identifier
- **WHEN** an authenticated delivery for the configured package has a nonempty message ID of up to 128 Unicode code points and a nonempty purchase token of up to 512 Unicode code points
- **THEN** accept their lengths and use the exact decoded identifiers for delivery tracking and purchase lookup
