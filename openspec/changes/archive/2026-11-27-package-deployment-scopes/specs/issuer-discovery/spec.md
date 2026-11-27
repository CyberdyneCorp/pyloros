## ADDED Requirements

### Requirement: Packaged base scopes
A build MAY include a space-separated base scope catalog through PYLOROS_BUILD_SCOPE_CATALOG. When OIDC_SCOPES is absent, both discovery routes SHALL use the packaged catalog or the portable default if the build has no catalog. An explicit runtime discovery setting SHALL override the packaged discovery base. Packaged scope names SHALL also be recognized by the administrative scope registry and protected-resource configuration.

#### Scenario: Catalog embedded during packaging
- **WHEN** the operator runs the packaged executable without an explicit runtime discovery catalog
- **THEN** discovery advertises the unique sorted union of packaged names and active database names

#### Scenario: Runtime discovery override
- **WHEN** an explicit discovery catalog is supplied to a packaged executable
- **THEN** discovery uses that catalog as its base and continues to reflect active database names
