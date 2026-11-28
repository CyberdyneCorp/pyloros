## ADDED Requirements

### Requirement: Decode provider HTTP responses
The service SHALL support identity, gzip and deflate content codings on both the token response and the subsequent user profile. Each decoded JSON document SHALL fit within one MiB.

#### Scenario: Provider uses different codings on consecutive requests
- **WHEN** the token endpoint returns gzip and the profile endpoint returns deflate
- **THEN** the service reads the token and processes the profile with the usual account mapping rules

#### Scenario: Decoded document exceeds the bound
- **WHEN** either decoded response exceeds one MiB
- **THEN** the provider exchange fails
