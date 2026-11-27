## Why

Clients submitting email verification tokens receive inconsistent errors depending on JSON encoding and body size.

## What Changes

Use the common JSON field validator at the email verification endpoint.

## Impact

This affects POST requests to the email verification endpoint and its input validation tests.
