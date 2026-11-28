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

### Requirement: PostgreSQL readiness failure details
Readiness SHALL distinguish refused connections, rejected credentials, denied database access and exhausted pool capacity. A failed revision query on a reachable database SHALL report a migration diagnostic. A single null revision SHALL report the same missing revision as an empty table.

#### Scenario: Database rejects authentication
- **WHEN** the PostgreSQL password is refused
- **THEN** readiness returns 503, both flags are false and the diagnostic is database unreachable: InvalidPasswordError

#### Scenario: PostgreSQL cancels the revision query
- **WHEN** a database statement or lock timeout interrupts the migration read
- **THEN** readiness returns 503 with database true and a migration DBAPIError diagnostic

### Requirement: Readiness during a migration lock
A probe holding a connection SHALL wait for PostgreSQL to finish the revision query. The default service pool SHALL admit up to fifteen concurrent connections. A readiness request waiting on a full pool SHALL wait up to thirty seconds for admission.

#### Scenario: Migration releases its lock
- **WHEN** the version table is locked for three seconds and then exposes the expected revision
- **THEN** the waiting readiness check returns 200 after the release

#### Scenario: Exhausted pool
- **WHEN** every connection remains busy through the readiness admission window
- **THEN** the waiting probe returns 503 with a TimeoutError diagnostic

### Requirement: Hook egress readiness
When hooks are enabled, readiness SHALL include a boolean indicating whether the service is running its hook egress proxy. Proxy availability SHALL be independent of the database readiness status.

#### Scenario: Listener cannot start
- **WHEN** the configured port is unavailable
- **THEN** readiness reports the proxy as unavailable and the auth service continues to handle requests

#### Scenario: Hooks disabled
- **WHEN** the operator disables hooks
- **THEN** readiness omits the proxy indicator and the service does not start a hook listener

#### Scenario: A hook requests network access
- **WHEN** the listener accepts a tunnel request
- **THEN** it permits only configured hosts and their subdomains on web ports and connects only to a verified public destination address

#### Scenario: A listener hostname resolves to multiple local addresses
- **WHEN** a required address is already bound
- **THEN** the proxy reports unavailable and releases any sockets it opened for the other addresses

### Requirement: Inspect PostgreSQL writer mode
The project SHALL provide a local cutover command that succeeds only when the configured PostgreSQL server is outside recovery and the current transaction permits writes. The command SHALL check both conditions on the same connection using a query with no data mutations. Connection and query errors SHALL yield an unsuccessful exit.

#### Scenario: Standby serves queries
- **WHEN** the connection reaches a server in recovery
- **THEN** report standby and exit unsuccessfully

#### Scenario: Read-only connection to the primary
- **WHEN** recovery is complete but the transaction is read-only
- **THEN** report read-only primary and exit unsuccessfully

#### Scenario: Writer promoted
- **WHEN** a new connection reaches the promoted server with a read-write transaction
- **THEN** report writable primary and exit successfully
