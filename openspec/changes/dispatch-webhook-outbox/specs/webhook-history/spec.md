## ADDED Requirements

### Requirement: Dispatch signed notifications
When webhook delivery is enabled, the service SHALL deliver queued notifications with bounded concurrency and retain a history of attempts.

#### Scenario: Sign the original event
- **WHEN** a worker claims a due delivery for an active subscription
- **THEN** send its stored body with a stable event identifier, attempt timestamp and signature for each active signing key

#### Scenario: Another worker retries after key rotation
- **WHEN** a subscription rotates its signing key after a failed attempt and another worker claims the retry during the overlap
- **THEN** sign the original message ID and body with the retry timestamp and supply signatures from both the current and previous keys

#### Scenario: Another worker retries after the overlap expires
- **WHEN** the retry is claimed after the previous key expires
- **THEN** send the same message ID and body with a signature from the current key alone

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

#### Scenario: Receiver closes during a fixed-length response
- **WHEN** the receiver closes an unencoded HTTP response before the declared length and before the excerpt limit
- **THEN** record a transport failure with the received and expected byte counts and leave the HTTP status and excerpt absent
- **AND** once the full excerpt has arrived, record the receiver's status and excerpt without waiting for more bytes

#### Scenario: Compressed excerpt ends at the HTTP body boundary
- **WHEN** a receiver sends the full HTTP body with gzip, raw deflate or zlib-wrapped deflate and the decoder produces an excerpt before the compression end marker
- **THEN** retain the receiver's status and the available decoded bytes up to the excerpt limit, and apply the usual retry rule for that status
