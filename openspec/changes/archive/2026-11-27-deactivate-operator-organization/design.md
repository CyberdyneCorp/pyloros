## Decisions

Reuse operator authentication, UUID validation and audit recording. Preserve primary and explicit membership references. Only write directory columns changed by the operation.

## Verification

Compare active and repeated requests, invalid targets, membership visibility and audit rollback across backends.
