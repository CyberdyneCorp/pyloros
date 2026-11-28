## ADDED Requirements

### Requirement: Enforce the passkey request size limit across chunks
The service SHALL enforce a limit of 65,536 body bytes before dispatching a passkey request, for both fixed-length and chunked uploads.

#### Scenario: Body ends at the limit
- **WHEN** the client finishes sending exactly 65,536 bytes
- **THEN** pass the complete body to the route for normal processing

#### Scenario: Final chunk crosses the limit
- **WHEN** the cumulative body size reaches 65,537 bytes
- **THEN** return HTTP 413 with the JSON detail "Passkey request too large" before invoking the route
