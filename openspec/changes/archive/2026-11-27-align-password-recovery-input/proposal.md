## Why

Password recovery clients need consistent validation errors when switching between servers during migration.

## What Changes

Decode recovery documents using the shared JSON reader. Preserve the submitted JSON in errors for both the address request and token redemption.

## Impact

The two password recovery POST routes will accept the same JSON encodings as email verification.
