## Decisions

Resolve the client from its service token. Reuse the operator assignment storage and organization eligibility rules. Attribute identity creation and assignment changes to the caller in the audit chain.

## Implementation status

PostgreSQL assignment changes, identity creation, audit entries and queued webhook deliveries share a transaction. A commit rejection returns HTTP 500. An active role hook requires the hook dispatcher.

Chain assignment checks use the selected catalog group and, when requested, its organization-bound group. Pyloros prepares unsigned membership calls for linked identities and reports provider errors before recording a successful assignment. Confirmed chain writes and the migration response contract for rejected writes remain open.
