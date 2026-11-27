## Decisions

Treat the boundary as a single policy reference per identity. On PostgreSQL, the mutation and its operator audit belong in one transaction. Grant sources remain independent of the boundary.

## Verification

Compare decisions and user detail after setting, replacing and clearing a boundary. Exercise missing targets, repeated operations, concurrent changes, historical policy documents, failed audits and provider switching.

Lock the identity row before changing its boundary on PostgreSQL. A clear must wait for a pending boundary insertion even when no boundary is visible to the initial request. Setting replaces the policy on the existing row, preserving its creation time. Chain resolution uses only identities supplied by the configured catalog.
