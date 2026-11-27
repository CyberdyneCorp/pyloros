## ADDED Requirements

### Requirement: Canonical API paths
Pyloros SHALL return a temporary redirect when removing trailing slashes from an otherwise unmatched URL identifies a registered API path.

#### Scenario: Alternate URL for a write
- **WHEN** a caller sends a mutation to the slash-suffixed form of a canonical route
- **THEN** return HTTP 307 with the canonical URL, the deployment request origin and the original query, before executing the mutation

#### Scenario: No matching route
- **WHEN** the URL and its canonical form are both unknown
- **THEN** return the ordinary missing-route response
