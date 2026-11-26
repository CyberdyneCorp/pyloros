## ADDED Requirements

### Requirement: Password attempt throttling
The login admission check SHALL charge each validated password attempt against a process-local source IP quota before looking up the account. Unresolved IPs SHALL share a quota. A positive limit SHALL allow that many immediate attempts and replenish evenly over one minute. A nonpositive limit SHALL disable throttling.

#### Scenario: Quota exhausted
- **WHEN** a caller has less than one attempt available
- **THEN** the check returns HTTP 429 with Retry-After of 60 seconds and records a rate-limited login failure for the attempted email

#### Scenario: Concurrent attempts
- **WHEN** simultaneous requests arrive for the same IP
- **THEN** each accepted attempt consumes a separate unit of available quota
