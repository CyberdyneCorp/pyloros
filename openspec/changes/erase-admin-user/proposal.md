## Why

An operator removing an account needs its associated records erased and a report of the outcome.

## What Changes

Support administrative account erasure, including records located through linked identities, and report deletion, pseudonymisation, retention and external processors.

## Capabilities

### Modified Capabilities

- `admin-user-inventory` gains account erasure.

## Impact

PostgreSQL changes, audit records and queued webhook deliveries must commit together. Deployments can supply their existing report language.
