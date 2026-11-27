## Registry data

Combine the deployment catalog and configured entries with the appropriate PostgreSQL records. Each collection preserves its ordering, supported filters and source-specific fields. Keep deployment-specific catalog text external to the public repository.

## Changes and visibility

Validate a change under the administrator's current permissions. Record the acting operator in the shared audit chain in the same transaction. Publish the local policy update after commit. Other replicas use their existing refresh interval. A failed transaction must leave both stored and effective policy unchanged.

## Verification

Compare collection and detail responses on shared fixtures. Exercise existing console and CLI operations. Verify that a successful change reaches each affected policy consumer, and that deactivation removes eligibility while retaining the administrative record.
