## Decisions

Resolve the user and existing IAM identity using the configured provider. PostgreSQL membership operations and their audits share a transaction. Protect the role namespace before applying an ordinary membership change.

## Verification

Exercise absent users and identities, absent groups, repeats and overlapping requests. Compare membership counts, effective permissions and audit records. Verify provider switching and chain confirmation separately.
