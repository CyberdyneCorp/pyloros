## Why

The IAM console loads policy and role inventories alongside groups. Operators need to see which policy attaches to a group and the session limits of the available roles.

## What Changes

Add read access to both inventories through the configured IAM provider.

## Capabilities

### New Capabilities

- `operator-iam-inventory` includes operator policy and role listings.

## Impact

The Rust backend serves the existing operator REST operations used by both the CLI and console.
