## ADDED Requirements

### Requirement: Enforce the decoded CSV field limit
The importer SHALL accept header and data fields up to 131,072 Unicode scalar values under the usual import rules. It SHALL return HTTP 500 for an otherwise valid file with a larger field, including an unused column. Such a rejection SHALL create no accounts or batch audit entry.

#### Scenario: Quoted or multibyte content reaches the limit
- **WHEN** an unused field contains 131,072 characters after CSV quote decoding
- **THEN** the importer processes the file, including when characters occupy multiple bytes in UTF-8

#### Scenario: An oversized field follows a valid account row
- **WHEN** a later CSV record contains a field of 131,073 characters
- **THEN** the importer rejects the whole upload before persisting the earlier account
