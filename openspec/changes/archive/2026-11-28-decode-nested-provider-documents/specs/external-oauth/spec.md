## ADDED Requirements

### Requirement: Nested provider response compression
The service SHALL decode up to eight gzip or deflate layers on independently encoded token and profile responses. It SHALL enforce the one MiB decoded document limit and require complete streams.

#### Scenario: A profile has multiple content codings
- **WHEN** a provider lists compression layers across combined or repeated encoding headers
- **THEN** decode them in reverse header order before mapping the profile

#### Scenario: Incomplete or oversized document
- **WHEN** any compressed layer ends prematurely or the decoded document exceeds one MiB
- **THEN** fail the exchange
