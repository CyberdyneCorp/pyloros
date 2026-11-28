## ADDED Requirements

### Requirement: Preserve the retry schedule after receiver throttling
After a first delivery attempt returns HTTP 429, the worker SHALL record the response and persist a retry time using the five-second base delay with up to ten percent jitter. The worker SHALL use this schedule for both delay-seconds and HTTP-date Retry-After values.

#### Scenario: Transfer a throttled delivery
- **WHEN** the original worker stops after recording the first attempt and another worker claims pending deliveries before the stored retry time
- **THEN** the throttled delivery remains pending
- **WHEN** the incoming worker claims it at or after the stored time
- **THEN** send the same event ID and body with a valid signature and retain the first attempt in its history
