## ADDED Requirements

### Requirement: Inspect the embedded scope catalog offline
The executable SHALL support a standalone --print-build-scope-catalog argument that prints the compile-time catalog as JSON and exits successfully without starting the service. Runtime discovery settings SHALL have no effect on the report.

#### Scenario: Portable executable
- **WHEN** the build had no explicit catalog
- **THEN** print JSON null

#### Scenario: Deployment-specific executable
- **WHEN** a catalog was supplied at build time
- **THEN** print the space-separated names as a JSON array in their supplied order, using an empty array for an explicit empty catalog
