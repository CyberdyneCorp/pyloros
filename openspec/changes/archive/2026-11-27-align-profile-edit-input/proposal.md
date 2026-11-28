## Why

Existing clients can send JSON in several Unicode encodings. Profile edits should retain the same validation behavior when a deployment changes backends.

## What Changes

Align request decoding and validation for the current-user edit operation.

## Capabilities

### Modified Capabilities

- `user-profile` gains request parsing guarantees for phone edits.

## Impact

Affects the profile edit handler and its HTTP errors.
