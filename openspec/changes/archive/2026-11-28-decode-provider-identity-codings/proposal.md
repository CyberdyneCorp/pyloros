## Why
A provider can include an identity layer when describing its compressed JSON response. The OAuth client must still read the token and account profile.

## What Changes
Recognize a single effective compression coding across combined and repeated Content-Encoding fields.

## Capabilities
### Modified Capabilities
- external-oauth

## Impact
Remote token and profile HTTP responses.
