## Why
The shared browser client needs to continue its login after its access token expires.
## What Changes
Rotate a signed first-party refresh credential, recompute account claims, preserve authentication context and handle concurrent use and replay.
## Capabilities
### Modified Capabilities
- grant-sessions
