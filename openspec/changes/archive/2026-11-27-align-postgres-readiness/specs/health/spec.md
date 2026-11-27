## ADDED Requirements

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
