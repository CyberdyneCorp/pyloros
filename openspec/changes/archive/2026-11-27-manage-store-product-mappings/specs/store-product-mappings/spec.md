## ADDED Requirements

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
