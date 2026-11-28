## ADDED Requirements

### Requirement: Read broad relationship graphs efficiently
The service SHALL group bounded outgoing object-edge reads for broad permission searches in the same client-scoped snapshot used for the decision. Traversal order and the rule and edge budgets SHALL apply to every visited object, including objects without outgoing object edges.

#### Scenario: Direct membership on a leaf
- **WHEN** a queued object has a direct user grant and no outgoing object edges
- **THEN** its eligible direct rule can prove access within the remaining work budget

#### Scenario: Multiple empty branches
- **WHEN** a search processes a group of at least eight queued objects with no outgoing object edges
- **THEN** a shared read allows the search to skip individual inherited relationship queries for those objects

#### Scenario: A populated branch exceeds the batch limit
- **WHEN** the batched read returns a partial list of an object's outgoing relationships
- **THEN** evaluation uses the full per-relation lookup within its decision budget, including eligible edges beyond the partial list
