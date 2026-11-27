## Decisions

Resolve the client from the authenticated service bearer, check role existence against the active IAM provider, then replace its PostgreSQL mapping in the same transaction as its audit entry. Share the operator validation and persistence paths.

## Open decisions

Mapping writes on Pyloros serialize per client and role. Each successful replacement sets the entire permission list. A rejected commit rolls back the mapping and audit and returns HTTP 500. Migration signoff depends on the agreed concurrency and failed-commit response contracts.
