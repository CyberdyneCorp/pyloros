## Why

Application deployments can update a relationship model while another replica grants an assignment that the proposed model would remove. Clients need to know which write took effect before retrying.

## What Changes

Document how the model and assignment endpoints resolve conflicting writes for one client.

## Capabilities

### Modified Capabilities

- `relationship-authorization`

## Impact

Clarifies existing API behavior for direct user assignments and object relationships.
