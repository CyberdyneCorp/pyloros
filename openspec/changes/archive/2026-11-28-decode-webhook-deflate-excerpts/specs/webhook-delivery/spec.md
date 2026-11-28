## ADDED Requirements

### Requirement: Decode deflate receiver excerpts
The webhook worker SHALL accept valid raw and zlib-wrapped streams labeled with HTTP content coding deflate. It SHALL retain at most the first 1,024 decoded bytes as the response excerpt, replacing incomplete or invalid UTF-8 when converting to text.

#### Scenario: A receiver acknowledges a retry with a raw deflate body
- **WHEN** a receiver returns HTTP 202 with a raw deflate response after a prior unsuccessful attempt
- **THEN** record the response code and decoded excerpt and mark the delivery successful

#### Scenario: A receiver reports a temporary failure
- **WHEN** a receiver returns HTTP 503 with a zlib-wrapped or raw deflate body while retries remain
- **THEN** record the response code and decoded excerpt and schedule a retry
