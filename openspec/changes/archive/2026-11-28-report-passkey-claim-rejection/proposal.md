## Why

A database refusal while claiming a challenge has different retry behavior from a failed credential write after the claim commits.

## What Changes

Return HTTP 500 for a database rejection of an authenticated ceremony claim. Document how the caller can recover using the original proof.

## Impact

Applies to registration and reauthentication verification and records the corresponding login behavior.
