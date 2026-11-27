## Decisions

Store the relationship separately from group membership and policy documents. Commit each PostgreSQL operation and its audit together. Resolve identifiers through the selected provider when using chain-backed IAM.

## Verification

Compare repeated requests, missing targets, authorization, audit failure and provider switches. Read the group inventory and evaluate access after each mutation. Exercise policy changes from the existing clients and check overlapping writes.

A successful PostgreSQL request records an audit even if the relationship already had the requested state. Attachment holds both referenced rows while inserting the relationship. Overlapping attach, detach and policy deletion requests require an explicit coexistence decision before cutover.
