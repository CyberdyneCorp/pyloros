## Why
A canary needs to publish webhook events while another service owns delivery. The existing switch controls both activities.

## What Changes
Allow an operator to disable outbound delivery on individual service processes independently of event creation.

## Capabilities
### New Capabilities
- webhook-delivery

## Impact
Worker startup configuration and rollout documentation.
