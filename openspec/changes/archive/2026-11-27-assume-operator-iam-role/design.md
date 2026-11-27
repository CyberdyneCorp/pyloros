## Decisions

Validate request fields before resolving the role through the configured provider. Use one start instant to derive the expiry. Keep distinct session records for repeated successful requests.

## Verification

Compare role and identity lookup failures, duration coercion and range errors, short-lived and immediately expired sessions, audit rollback, and the unchanged clients. Check both services can list, evaluate and revoke a session created by the other.
