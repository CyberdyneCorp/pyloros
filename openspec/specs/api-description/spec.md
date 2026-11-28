# api-description Specification

## Purpose

Let clients discover the API description selected by a deployment.

## Requirements

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

### Requirement: Serve deployment browser documentation
When a deployment supplies the schema and documentation bundle, the server SHALL offer Swagger UI, ReDoc and the Swagger OAuth callback according to the documentation switch. The default SHALL enable pages outside production and disable them in production.

#### Scenario: Open documentation
- **WHEN** documentation is enabled and a browser requests /docs, /redoc or /docs/oauth2-redirect
- **THEN** GET returns the supplied HTML, HEAD reports its length, and a trailing slash redirects with the query preserved

#### Scenario: Disable interactive documentation
- **WHEN** documentation is disabled
- **THEN** the pages return the standard missing-route response and the configured JSON schema remains available

#### Scenario: Apply browser policy at path boundaries
- **WHEN** a deployment provides a schema policy
- **THEN** it applies to the schema and documentation path namespaces, including missing descendants, while unrelated paths retain their own policy
