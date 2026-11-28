## ADDED Requirements

### Requirement: Read raw deflate provider documents
The service SHALL accept raw DEFLATE and zlib-wrapped DEFLATE under the deflate content coding for remote OAuth token and profile JSON responses.

#### Scenario: Provider uses different deflate representations
- **WHEN** either endpoint returns raw deflate and the other returns a supported encoding
- **THEN** decode each document independently and apply the existing one MiB decoded size limit to each
