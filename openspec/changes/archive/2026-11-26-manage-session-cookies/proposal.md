## Why
The existing browser client relies on cookie scope, visibility and lifetime when a login succeeds or a session ends.

## What Changes
Provide a shared session cookie writer and align its security settings with the request middleware.

## Capabilities
### Modified Capabilities
- http-responses
