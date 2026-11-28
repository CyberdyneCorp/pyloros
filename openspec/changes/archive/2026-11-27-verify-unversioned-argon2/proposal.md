## Why

Users and service clients with older Argon2 credentials can receive an invalid-credential response even when they submit the correct secret.

## What Changes

Interpret an omitted version field in an Argon2 hash as version 16. Use the version recorded in hashes that specify one.

## Impact

The shared verifier covers account passwords and OAuth client secrets. Password writes continue to use the configured scheme and its current parameters.
