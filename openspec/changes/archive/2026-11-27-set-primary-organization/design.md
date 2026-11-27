## Decisions

Apply operator access control and validate the user and optional organization identifiers. Require an active target organization for assignments. Reuse membership creation semantics and retain explicit membership rows when the primary is cleared.

## Verification

Compare the recorded actor and target, membership state and effective entitlements using both backends. Compare concurrent assignments, retries and rollback on audit failure.
