## Decisions

Resolve the user and existing IAM identity using the configured provider. PostgreSQL membership operations and their audits share a transaction. Protect the role namespace before applying an ordinary membership change.

## Verification

Exercise absent users and identities, absent groups, repeats and overlapping requests. Compare membership counts, effective permissions and audit records. Verify provider switching and chain confirmation separately.

PostgreSQL holds a shared lock on the group while checking its namespace and changing membership. Duplicate successful requests each record an operator audit. A chain request that fails during preparation returns an error and leaves the operator audit unchanged. Failed chain writes and concurrent requests remain explicit compatibility decisions.
