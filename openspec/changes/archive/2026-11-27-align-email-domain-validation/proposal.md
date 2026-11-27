## Why

Some addresses pass recovery validation on one server and fail on the other. Clients also use field diagnostics to help users correct malformed domains.

## What Changes

Validate domain characters, DNS lengths, reserved domains and IP literals at the shared account address boundary. Report common at-sign substitutions.

## Impact

Account endpoints that accept an email address will apply the same domain policy.
