## ADDED Requirements

### Requirement: Read provider JSON in Unicode encodings
The service SHALL accept UTF-8, UTF-16 and UTF-32 token and profile JSON documents, with or without a byte order mark and in either applicable byte order. The one MiB limit SHALL apply to the document bytes after HTTP decompression and before text conversion.

#### Scenario: Different text encodings during a single exchange
- **WHEN** a provider returns a UTF-16 token response followed by a UTF-32 profile
- **THEN** process both documents and preserve the Unicode subject

#### Scenario: Invalid encoding
- **WHEN** either document contains truncated Unicode code units
- **THEN** reject the exchange
