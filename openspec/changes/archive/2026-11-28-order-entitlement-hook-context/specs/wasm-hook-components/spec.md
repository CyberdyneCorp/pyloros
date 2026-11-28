## ADDED Requirements

### Requirement: Preserve displayed entitlement context order
The worker SHALL deliver the stored fields of entitlement grants and revocations in source order for personal and organization owners.

#### Scenario: Display a grant
- **WHEN** a grant delivery is claimed
- **THEN** emit product key, plan, entitlement ID, source, organization ID, event type and user ID in that order with their stored values

#### Scenario: Display a withdrawal
- **WHEN** a revocation delivery is claimed
- **THEN** emit product key, plan, entitlement ID, event type and user ID in that order, preserving a null plan or user ID
