## Decisions

Count the stored permissions for the client. Preserve existing entries until explicitly removed. A duplicate key receives the duplicate diagnostic even in a full catalog. A retired permission may be created again once capacity permits. Its prior role mappings remain removed.

## Verification

Start with 257 stored keys. Alternate administrator and delegated writes across services, compare opposite-backend reads after each request, and reconcile successful changes with their audit actors.
