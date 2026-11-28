## Why

A context-printing hook exposes field order. Queued login deliveries currently display fields in PostgreSQL JSONB storage order.

## What Changes

Order the permitted login fields at execution so the same hook produces the same history when either backend handles sign-in.

## Impact

Applies to committed login deliveries, including pending rows created by an older producer.
