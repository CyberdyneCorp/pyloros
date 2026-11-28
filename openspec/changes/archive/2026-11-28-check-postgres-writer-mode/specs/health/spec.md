## ADDED Requirements

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
