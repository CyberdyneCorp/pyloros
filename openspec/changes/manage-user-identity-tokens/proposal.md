## Why

Operators need to recover failed identity token issuance and manage an issued token's status through the existing user administration clients.

## What Changes

Support mint retries and status changes through the configured blockchain provider and expose the resulting state through the user token read.

## Capabilities

### Modified Capabilities
- `operator-iam-inventory` gains identity token administration.

## Impact

Operator routes, user metadata, local provider lifecycle, chain calls and audit records.
