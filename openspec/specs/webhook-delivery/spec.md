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
