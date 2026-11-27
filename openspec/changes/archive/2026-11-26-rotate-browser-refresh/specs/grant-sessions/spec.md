## ADDED Requirements

### Requirement: Rotate a first-party refresh token
The browser refresh endpoint SHALL accept a refresh cookie or JSON token, prefer the cookie, and issue a new pair only for a live first-party session belonging to an active account. It SHALL preserve the session identity and original authentication context, reevaluate account claims, and record rotation and activity atomically.

#### Scenario: Concurrent refresh
- **WHEN** multiple requests compete to claim one live token
- **THEN** at most one succeeds and a losing claim returns an authentication error.

#### Scenario: Reuse after rotation
- **WHEN** a replaced credential is reused inside the configured grace interval and its successor exists
- **THEN** reject the request while keeping the session usable.

#### Scenario: Replay outside grace
- **WHEN** an otherwise valid credential for the session is unknown or reused outside grace
- **THEN** revoke the session and its remaining refresh credentials before returning the error.
