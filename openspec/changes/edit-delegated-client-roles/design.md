## Decisions

Use the authenticated client as the catalog owner and audit actor. Reuse the provider and mutation paths used for operator requests. With PostgreSQL, write catalog changes and audit information together.

## Implementation status

PostgreSQL serializes catalog edits per client and reports a server error when a transaction fails to commit. The rollout contract for competing writes and deferred rollback is open.

For a deployed provider, creation prepares the group call with the client-qualified name. Deletion resolves the selected group again before preparing its removal and handles organization-bound groups first. Submission, confirmation, and post-confirmation persistence remain pending.
