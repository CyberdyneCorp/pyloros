# Health probes

## Purpose

Allow operators to distinguish a serving process from a deployment ready to use its database.

## Requirements

### Requirement: Process liveness
GET `/api/v1/health` SHALL return HTTP 200 and a JSON object with `status` set to `healthy`, the build version in `version`, and the configured environment in `environment`, independently of database connectivity.

#### Scenario: Database unavailable
- **WHEN** the database connection pool is closed and a caller requests liveness
- **THEN** the process returns the healthy response

### Requirement: Database readiness
GET `/api/v1/health/ready` SHALL return HTTP 200 only when PostgreSQL responds and the migration table contains exactly one revision matching the running build. The response SHALL include `database`, `migrations`, `status` and `version`. On failure the service SHALL return HTTP 503 with a diagnostic in `detail`.

#### Scenario: Matching schema
- **WHEN** the database is reachable and its sole revision matches the build
- **THEN** both flags are true, status is `ready`, and the response omits `detail`

#### Scenario: Schema unavailable or incompatible
- **WHEN** the database responds but the revision table is missing, empty, contains multiple revisions, or reports a different revision
- **THEN** status is `not_ready`, database is true and migrations is false

#### Scenario: Connection unavailable
- **WHEN** the probe cannot reach the database
- **THEN** status is `not_ready` and both flags are false

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
