## Why

Clients retiring a relation may revoke its last assignment and replace the model through different replicas. They need to know which write to retry after a conflict.

## What Changes

Document the two possible commit orders and the audit effects of retrying each request.

## Impact

Clarifies existing model replacement and relationship deletion behavior on PostgreSQL.
