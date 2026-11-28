## Why

A provider can serve the token response or user profile with HTTP content coding. Both documents must reach the existing JSON parser as decoded bytes.

## What Changes

Negotiate gzip and deflate in the external sign-in HTTP client and enforce the existing size bound on the decoded response.

## Impact

Applies to remote Google and Microsoft sign-in exchanges.
