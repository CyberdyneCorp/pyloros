## ADDED Requirements

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
