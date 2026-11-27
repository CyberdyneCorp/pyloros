## Decisions

Use the configured IAM provider. Protect client-role groups before mutating state. PostgreSQL must remove the group and its membership and policy links in the same transaction as the audit. Preserve independently stored identities and policies.

## Verification

Compare missing, protected and populated groups, permission decisions following deletion, failure rollback, concurrent deletes and unchanged clients. Exercise chain rejection and confirmation separately.
