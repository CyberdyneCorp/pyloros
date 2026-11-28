## Why

A rejected revocation commit can return an inventory availability error even though the credential is still readable.

## What Changes

Apply the explicit commit rejection response to account passkey removal.

## Impact

Changes the response to a rejected account passkey revocation and adds database regression coverage.
