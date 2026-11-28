## Why
Each hook producer can move independently. The global exit status alone cannot establish whether registration is ready to switch.

## What Changes
Accept an optional event name in the binding check and expose it through the existing just recipe.

## Capabilities
### Modified Capabilities
- admin-hook-inventory

## Impact
Operator CLI, recipe and read-only inventory query.
