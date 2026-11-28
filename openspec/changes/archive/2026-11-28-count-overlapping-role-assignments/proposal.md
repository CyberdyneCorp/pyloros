## Why

Registered client IDs can overlap even when there are no stored role memberships under either namespace. Operators need aggregate assignment counts before choosing how to migrate those clients.

## What Changes

Add a PostgreSQL assignment summary to the existing registry overlap command.

## Impact

The optional report requires column-level read access to the group and membership tables.
