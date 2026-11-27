## Why

Account recovery can return success while failing to find the account when a client sends the ASCII spelling of an internationalized domain or a decomposed Unicode local part.

## What Changes

Normalize accepted account email addresses at the shared input validator before account lookup, registration and recovery.

## Impact

This affects the spelling of internationalized addresses passed to account services. Operators should inventory historical noncanonical addresses and resolve any conflicting owners before cutover.
