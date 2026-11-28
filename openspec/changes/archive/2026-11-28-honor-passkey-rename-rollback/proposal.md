## Why

A rejected rename currently reports that inventory is unavailable even though the credential remains readable.

## What Changes

Apply the existing explicit commit rejection response to credential renames.

## Impact

Affects the passkey management PATCH response and its regression coverage.
