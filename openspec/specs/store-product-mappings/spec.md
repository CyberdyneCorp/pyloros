# store-product-mappings Specification

## Purpose
Define how administrators browse virtual products and manage the mobile storefront identifiers associated with them.

## Requirements

### Requirement: Manage storefront mappings
Pyloros SHALL allow first-party administrators to list, create and delete product mappings independently for the Apple and Google storefronts.

#### Scenario: List mappings
- **WHEN** an administrator reads a storefront collection
- **THEN** return its total and a page ordered by storefront identifier with a default size of 50 and a maximum size of 200

#### Scenario: Register a mapping
- **WHEN** an administrator submits a new storefront identifier with an eligible product and optional plan
- **THEN** return the created mapping with its timestamp and record the actor and product details in the audit chain

#### Scenario: Reject an ineligible product
- **WHEN** the key resolves to an inactive or dynamically registered client, or resolves to neither a client nor an active virtual product
- **THEN** reject the request before checking for a duplicate mapping

#### Scenario: Remove a mapping
- **WHEN** an administrator deletes an existing mapping
- **THEN** record its removal and return an empty successful response

#### Scenario: Audit persistence fails
- **WHEN** recording a mapping mutation fails
- **THEN** roll back the mutation together with its audit record

### Requirement: Browse the virtual product catalog
Pyloros SHALL provide a paginated administrative product directory for storefront product selection.

#### Scenario: Select an active virtual product
- **WHEN** the operator filters the directory to active products
- **THEN** return only active virtual products in product-key order and report their filtered total

#### Scenario: Stored operator metadata is unreadable
- **WHEN** the current operator account contains metadata that cannot be loaded as an object or a supported legacy key-value sequence
- **THEN** the administrative request fails before product lookup or mutation

### Requirement: Manage virtual products
Pyloros SHALL allow a first-party administrator to register, update and deactivate a virtual product and audit each accepted operation.

#### Scenario: Register a product
- **WHEN** the administrator supplies an unused, valid product key and a display name
- **THEN** return the active product, its timestamps and its optional description

#### Scenario: Edit selected fields
- **WHEN** an administrator patches a product
- **THEN** retain omitted fields, clear an explicitly null description and record which recognized fields were submitted

#### Scenario: Deactivate and reactivate
- **WHEN** the administrator deletes a product
- **THEN** deactivate the existing record and retain its key for future reactivation by patch

#### Scenario: Audit failure
- **WHEN** the audit entry for a mutation cannot be persisted
- **THEN** the product change rolls back

#### Scenario: Invalid numeric input for a nullable field
- **WHEN** a product update supplies an out-of-range number in a nullable field
- **THEN** reject the request and retain the stored product

### Requirement: Product writes accept padded JSON documents
The API SHALL process JSON for virtual product creation and patching and for storefront mapping creation when whitespace or the document encoding takes the request above two MiB.

#### Scenario: Whitespace around a product write
- **WHEN** an administrator submits a valid UTF-8, UTF-16 or UTF-32 document with trailing JSON whitespace
- **THEN** the operation applies the requested change and returns the saved product or mapping

#### Scenario: Invalid or unauthenticated product write
- **WHEN** a padded JSON document contains invalid product fields or the caller lacks authentication
- **THEN** the API applies the same authentication and field validation rules as for a compact document
