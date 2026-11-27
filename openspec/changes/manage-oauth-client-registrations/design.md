## Approach

Reuse the administrative read authorization policy and client response representation. Validate the resulting registration before storing a change. Preserve the distinction between an omitted field, a supported explicit null, and an empty collection. Share the audit-chain writer across registration paths.

## Verification

Compare validation and policy decisions, response metadata, stored credentials and audit events. Exercise client authentication on the other backend after creation, rotation and deactivation. Check grace-window expiry, rollback on failed audit, and edits issued using the existing administrative tools.
