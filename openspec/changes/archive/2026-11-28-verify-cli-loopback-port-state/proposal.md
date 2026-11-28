## Why

Clients can submit more than one loopback port parameter or use a padded integer. The selected port must survive a backend handoff.

## What Changes

Document how CLI sign-in validates the last submitted port and binds its integer value to callback state.

## Capabilities

### Modified Capabilities

- external-oauth

## Impact

OAuth initiation and loopback callback compatibility checks.
