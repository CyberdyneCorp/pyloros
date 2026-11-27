## Decisions

Resolve the role against the configured provider. Use the stored active flag and expiry instant when reading PostgreSQL. A chain provider can confirm a role while exposing an empty session inventory.

## Verification

Compare responses for missing roles, repeated sessions for one identity, disabled and expired sessions, and unavailable providers. Exercise the unchanged roles panel and CLI.
