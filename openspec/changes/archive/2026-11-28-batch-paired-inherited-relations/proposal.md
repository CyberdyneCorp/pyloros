## Why

Checking two inherited proofs currently needs two sequential destination reads on an individual node. Database transport delays make that extra exchange observable.

## What Changes

Read the bounded destinations for paired inherited proofs in one statement.

## Impact

The existing relationship check uses the same snapshot, rule order and traversal budget.
