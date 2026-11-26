## Decisions

Load a snapshot before serving, then refresh on a timer. Publish successful reads atomically to both metadata routes. Keep the latest snapshot through an outage and allow the HTTP request path to proceed independently of PostgreSQL.
