## Approach

Reuse first-party administrator authentication and existing REST validation. Read session metadata and owner email from PostgreSQL with one join per page. Apply the same filters to the total and the page. Bind the activity cutoff once per request.

For revocation, compare session state, refresh records, authentication events and the operator audit chain with a running reference. Exercise the existing clients and cross-backend refresh.

## Concurrent refresh

The Rust refresh and revocation paths lock the session before changing refresh tokens. A concurrent refresh on a writer that locks tokens first can encounter a PostgreSQL deadlock. The database rolls back one transaction. A successful revocation must leave the entire token family unusable. Mixed-writer rollout remains open until the writers use consistent locking or deployment routing provides equivalent serialization.
