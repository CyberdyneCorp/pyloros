## Why

A subscription can be disabled while an event is waiting for a retry. Operators need to distinguish a stopped delivery from an additional network attempt.

## What Changes

Describe how the worker stops a due retry and how an operator restarts that delivery after reactivation.

## Capabilities

### Modified Capabilities

- webhook-delivery

## Impact

Delivery history, worker handoff and operator redelivery.
