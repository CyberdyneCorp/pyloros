## ADDED Requirements

### Requirement: Discovery scope refresh
When discovery is enabled, each replica SHALL load active PostgreSQL scope names at startup and at the configured refresh interval, which defaults to 30 seconds. Both metadata documents SHALL advertise the sorted union of these names and the configured base scopes. An interval of zero SHALL disable database loading.

#### Scenario: Catalog changes after startup
- **WHEN** a database-only scope is activated or removed
- **THEN** both documents reflect the change after the next successful refresh

#### Scenario: Registry read fails
- **WHEN** a refresh fails
- **THEN** discovery continues to serve the last successful scope set, or its base scopes if no refresh has succeeded
