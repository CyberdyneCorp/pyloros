## ADDED Requirements

### Requirement: Health probe method and schema errors

Health probes SHALL advertise GET on method refusal and return 405 for HEAD. Readiness SHALL distinguish a missing migration table from multiple applied revisions.

#### Scenario: Unsupported probe method
- **WHEN** a client sends POST to a probe
- **THEN** return a 405 problem document and an Allow header listing GET.

#### Scenario: Multiple revisions
- **WHEN** PostgreSQL responds with two revision rows
- **THEN** return 503 with the multiple-results diagnostic and report that the database is reachable.

#### Scenario: Trailing slash on a probe
- **WHEN** a client uses the trailing-slash spelling of a probe URL
- **THEN** return a temporary 307 redirect to the canonical URL with its query string intact.
