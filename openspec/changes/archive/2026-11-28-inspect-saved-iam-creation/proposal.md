## Why
A successful transaction can carry a creation event whose identifier is encoded differently from what the operator API expects. Operators need to check the receipt layout against the migration build.

## What Changes
Read a saved receipt and report candidate identifiers for the requested creation kind.

## Capabilities
- Modified capability: chain-iam-transactions
