## Decisions

Resolve the operator and selected provider before resolving the policy. On PostgreSQL protect the policy from concurrent attachment while checking usage, removing the policy and recording the audit. A failed audit must leave the policy intact.

## Verification

Exercise missing policies, all forms of attachment, rollback, repeated deletion and concurrent changes. Check the original clients and confirm that switching providers selects the correct policy store.
