## Decisions

Use the configured IAM provider. Protect client-role groups before mutating state. PostgreSQL must remove the group and its membership and policy links in the same transaction as the audit. Preserve independently stored identities and policies.

## Verification

Compare missing, protected and populated groups, permission decisions following deletion, failure rollback, concurrent deletes and unchanged clients. Exercise chain rejection and confirmation separately.

PostgreSQL locks the group before checking its current name. A deletion that waits for a rename into the client-role namespace must preserve the group. A second deletion that finds the row gone returns a missing-group response without recording another successful deletion. During chain preparation, check the name again when resolving the contract identifier.
