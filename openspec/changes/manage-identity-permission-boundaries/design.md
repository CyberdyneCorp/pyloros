## Decisions

Treat the boundary as a single policy reference per identity. On PostgreSQL, the mutation and its operator audit belong in one transaction. Grant sources remain independent of the boundary.

## Verification

Compare decisions and user detail after setting, replacing and clearing a boundary. Exercise missing targets, repeated operations, concurrent changes, historical policy documents, failed audits and provider switching.
