# webhook-delivery Specification

## Purpose
Deliver queued outbound webhook events and support transferring delivery ownership between service processes.

## Requirements

### Requirement: Assign webhook delivery ownership independently of event creation
A process SHALL start the webhook worker when webhooks and its local worker setting are both enabled. The local setting SHALL default to enabled. Disabling the local worker SHALL allow enabled event producers to persist events and deliveries for another worker.

#### Scenario: Canary with an external delivery owner
- **WHEN** webhooks are enabled and PYLOROS_WEBHOOK_WORKER_ENABLED is false
- **THEN** publish eligible events normally and leave queued deliveries available to the designated worker

#### Scenario: Resume pending deliveries
- **WHEN** an enabled worker starts against the shared database
- **THEN** claim due deliveries according to the existing lease and retry rules

#### Scenario: Global feature disabled
- **WHEN** WEBHOOKS_ENABLED is false
- **THEN** skip worker startup even if the local worker setting is true

### Requirement: Decode deflate receiver excerpts
The webhook worker SHALL accept valid raw and zlib-wrapped streams labeled with HTTP content coding deflate. It SHALL retain at most the first 1,024 decoded bytes as the response excerpt, replacing incomplete or invalid UTF-8 when converting to text.

#### Scenario: A receiver acknowledges a retry with a raw deflate body
- **WHEN** a receiver returns HTTP 202 with a raw deflate response after a prior unsuccessful attempt
- **THEN** record the response code and decoded excerpt and mark the delivery successful

#### Scenario: A receiver reports a temporary failure
- **WHEN** a receiver returns HTTP 503 with a zlib-wrapped or raw deflate body while retries remain
- **THEN** record the response code and decoded excerpt and schedule a retry

### Requirement: Preserve the retry schedule after receiver throttling
After a first delivery attempt returns HTTP 429, the worker SHALL record the response and persist a retry time using the five-second base delay with up to ten percent jitter. The worker SHALL use this schedule for both delay-seconds and HTTP-date Retry-After values.

#### Scenario: Transfer a throttled delivery
- **WHEN** the original worker stops after recording the first attempt and another worker claims pending deliveries before the stored retry time
- **THEN** the throttled delivery remains pending
- **WHEN** the incoming worker claims it at or after the stored time
- **THEN** send the same event ID and body with a valid signature and retain the first attempt in its history

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
