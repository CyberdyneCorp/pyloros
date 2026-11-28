## Why
Some OAuth provider transports send a raw deflate stream under the same content coding as a zlib-wrapped stream.

## What Changes
Recognize both representations during streaming reads of token and profile documents.

## Capabilities
### Modified Capabilities
- external-oauth

## Impact
Remote OAuth provider response decoding.
