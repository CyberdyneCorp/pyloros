## Decisions

Use the existing traversal batch threshold. For a batch sharing one object type, permission and direct rule, query the IDs whose rule fits the remaining budget. Constrain the query by tenant, user and relation in the existing snapshot. Charge each eligible rule and mark the decision incomplete when the budget truncates the batch. Other rule combinations keep their existing traversal.

## Verification

Trace an inherited check across 32 teams. Verify denial, a grant on the final team and a budget ending immediately before that grant.
