## Why
Character assignments differ across Unicode versions. A hook that prints its context can therefore change observable output during migration.

## What Changes
Provide a separate context-display component using Unicode 15.0 general categories.

## Impact
Operators can build and compare both variants before selecting a component digest.
