## Why

A verified enrollment or reauthentication can return an availability error when the final transaction is explicitly rejected. Clients also need to know whether the original ceremony can be retried.

## What Changes

Apply the existing commit rejection response to both authenticated completion routes and specify recovery after the proof has been claimed.

## Impact

Affects passkey registration and reauthentication verification.
