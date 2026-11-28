## ADDED Requirements

### Requirement: Publish a deployment API description
When an operator configures an OpenAPI document, the server SHALL load it at startup and serve it as JSON at /openapi.json. An unreadable or malformed configured document SHALL prevent startup. Without configuration the route SHALL be absent.

#### Scenario: Client discovers the schema
- **WHEN** a client requests the configured document using GET or HEAD
- **THEN** the server responds with the JSON media type and the document length
- **AND** GET returns the supplied bytes while HEAD has an empty body

#### Scenario: Discovery client follows a canonical redirect
- **WHEN** a client requests the schema with a trailing slash and query parameters
- **THEN** the server redirects to the canonical path and preserves the query

#### Scenario: Deployment supplies a schema-specific content policy
- **WHEN** the operator supplies a Content-Security-Policy for the schema
- **THEN** apply it to the document, its canonical redirect and method refusals
