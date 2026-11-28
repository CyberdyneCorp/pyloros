## ADDED Requirements

### Requirement: Persist the selected CLI loopback port
CLI initiation SHALL select the last submitted cli_port, parse it using the shared integer text rules and persist its numeric value for callback delivery. A syntactically invalid port SHALL return HTTP 422. A parsed value outside 1024 through 65535 SHALL return HTTP 400 in CLI mode. Both errors SHALL leave the state inventory unchanged.

#### Scenario: Return to the listener selected at initiation
- **WHEN** a client submits an invalid first port followed by a valid zero-padded port and completes sign-in on another backend
- **THEN** the callback redirects to the numeric port stored at initiation with a single-use code bound to the original challenge
