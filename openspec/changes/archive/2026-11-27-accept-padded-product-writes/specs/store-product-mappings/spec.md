## ADDED Requirements

### Requirement: Product writes accept padded JSON documents
The API SHALL process JSON for virtual product creation and patching and for storefront mapping creation when whitespace or the document encoding takes the request above two MiB.

#### Scenario: Whitespace around a product write
- **WHEN** an administrator submits a valid UTF-8, UTF-16 or UTF-32 document with trailing JSON whitespace
- **THEN** the operation applies the requested change and returns the saved product or mapping

#### Scenario: Invalid or unauthenticated product write
- **WHEN** a padded JSON document contains invalid product fields or the caller lacks authentication
- **THEN** the API applies the same authentication and field validation rules as for a compact document
