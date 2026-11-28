## ADDED Requirements

### Requirement: Dispatch signed notifications
When webhook delivery is enabled, the service SHALL deliver queued notifications with bounded concurrency and retain a history of attempts.

#### Scenario: Sign the original event
- **WHEN** a worker claims a due delivery for an active subscription
- **THEN** send its stored body with a stable event identifier, attempt timestamp and signature for each active signing key

#### Scenario: Recover or retry
- **WHEN** a delivery fails or its worker stops
- **THEN** record completed attempts atomically, retry within the attempt budget and make abandoned leases eligible for another worker

#### Scenario: Enforce destination policy
- **WHEN** sending a production notification
- **THEN** use HTTPS with certificate verification, connect only to an approved public address, and decline redirects

#### Scenario: Authenticate an HTTPS receiver
- **WHEN** the receiver presents a certificate issued by a trusted authority for its configured hostname
- **THEN** send the signed event and record the receiver's HTTP outcome
- **AND** reject a certificate for another hostname before transmitting the event
