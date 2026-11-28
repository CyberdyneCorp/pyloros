## Decisions

After confirming the primary and the current service grant, select the model and an indexed account existence predicate together. An absent model produces no row. Validate the model and requested permission before considering the account flag. Relationship traversal uses the same repeatable-read transaction.

## Verification

Compare PostgreSQL traces for direct, inherited and denied checks. Verify missing models, unknown permissions and inactive accounts through the HTTP entry point.
