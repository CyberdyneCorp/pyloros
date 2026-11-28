## Decisions
Select active subscriptions when publishing the role event in the mutation transaction. Persist a shared event and one delivery per recipient so subscription filter edits affect future role writes. Test the stored event and recipient IDs across successive changes.
