## ADDED Requirements

### Requirement: Stop due retries for disabled subscriptions
The worker SHALL mark a pending delivery failed when it becomes due for a disabled subscription. It SHALL retain the previous HTTP status, attempt count and attempt history, record the inactive subscription as the reason, and send no request for the stopped retry.

#### Scenario: Disable after an unsuccessful attempt
- **WHEN** the receiver returned HTTP 503 and an administrator disables the subscription before another worker claims its due retry
- **THEN** history shows the failed delivery, the inactive-subscription reason, and the single HTTP 503 attempt

#### Scenario: Recover the stopped event
- **WHEN** an administrator requests redelivery while the subscription is disabled
- **THEN** return HTTP 409
- **WHEN** the administrator reactivates the subscription
- **THEN** the stopped delivery remains failed until explicitly queued again
- **WHEN** an explicit redelivery succeeds
- **THEN** send the original event ID and body, retain both recorded attempts, and report one attempt in the new retry budget
