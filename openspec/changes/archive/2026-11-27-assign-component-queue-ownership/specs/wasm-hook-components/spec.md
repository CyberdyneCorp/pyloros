## ADDED Requirements

### Requirement: Assign component delivery ownership
With hooks enabled, PYLOROS_COMPONENT_WORKER_ENABLED SHALL select whether this process consumes queued component deliveries independently of which producer types it dispatches. When omitted, the service SHALL start the worker if any producer is enabled. Disabling hooks globally SHALL suppress the worker.

#### Scenario: Publisher-only replica
- **WHEN** a producer commits an eligible event while local execution is disabled
- **THEN** persist the selected component delivery for another worker

#### Scenario: Dedicated draining worker
- **WHEN** a process enables execution with no producers selected
- **THEN** process due deliveries from the shared queue using their stored component selections
