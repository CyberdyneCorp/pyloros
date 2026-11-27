Serialize assignments with user and client row locks. Check current organization membership before creating a scoped group. Commit the assignment, any new identity, audit and subscribed webhook deliveries together. Preserve the chain authority when configured.

A configured role-grant hook requires dispatcher support. When that dispatcher is unavailable, refuse the mutation before committing state. Chain writes require a separate provider implementation.
