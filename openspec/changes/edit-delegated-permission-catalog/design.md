## Decisions

Share catalog mutation logic with operator requests. Select the authorization path from the route and derive delegated ownership from the verified caller. Commit the catalog mutation and the service actor audit entry together. Include the client identifier in the canonical hash for service actors and retain the existing encoding for user actors.

## Open decisions

Pyloros currently returns HTTP 500 when the commit fails and rolls back both the catalog mutation and audit row. It also serializes capacity checks so concurrent additions keep each catalog within 256 entries. Migration signoff for creation and deletion depends on the commit-failure contract. Creation also depends on the concurrency contract at the catalog limit.
