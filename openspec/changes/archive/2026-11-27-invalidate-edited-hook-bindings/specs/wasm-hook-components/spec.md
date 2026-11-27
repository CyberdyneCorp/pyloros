## ADDED Requirements

### Requirement: Invalidate a component selection on source edits
The service SHALL clear a hook’s selected component when any writer commits a change to its stored source.

#### Scenario: Committed edit
- **WHEN** source text changes for a bound hook
- **THEN** clear its binding in the edit transaction and require selection before dispatching future events to that hook
- **AND** retain the pinned versions of previously queued deliveries

#### Scenario: Settings change or aborted edit
- **WHEN** a writer updates settings without changing source, resubmits identical source or rolls back a source edit
- **THEN** preserve the hook’s prior selection
