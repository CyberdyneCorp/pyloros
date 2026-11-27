## Decisions
Use the login producer and its recipient privacy controls. Grant consumption, session, success audit and deliveries share the transaction. A missing component binding leaves the grant retryable. A completed user grant under HS256 that requests an ID token retains its session, audit and delivery, marks the code consumed without a bound session, and returns the signing error.
