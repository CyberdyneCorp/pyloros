## Decisions

Resolve the operator and selected provider before resolving the policy. On PostgreSQL protect the policy from concurrent attachment while checking usage, removing the policy and recording the audit. A failed audit must leave the policy intact.

### Concurrent changes

On PostgreSQL, a committed attachment prevents a waiting Rust deletion. A second Rust deletion sees the policy as missing after the first commits. Record the differences observed with other writers before enabling mixed-writer rollout.

## Verification

Exercise missing policies, all forms of attachment, rollback, repeated deletion and concurrent changes. Check the original clients and confirm that switching providers selects the correct policy store.
