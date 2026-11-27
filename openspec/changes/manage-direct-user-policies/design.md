## Decisions

Resolve the target user and its identity before editing the direct policy relationship. PostgreSQL changes and operator audit records share a transaction. Preserve independent group grants and permission boundaries.

## Verification

Check repeated operations, missing users and policies, historical identity data, concurrent edits, and failed audit writes. Verify direct assignments in the user detail response and compare effective access decisions. Exercise the existing clients and selected chain provider.
