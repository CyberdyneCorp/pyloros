## Decisions

Carry the claimed session ID alongside the resolved grant. Use a JOSE signing library with a fixed algorithm. Bind the stored token identifier, user, client, resource, expiry and consented scopes to the session. The caller owns the transaction until access and ID tokens and required records have also been created.
