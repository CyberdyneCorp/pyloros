## ADDED Requirements

### Requirement: Select deployment assets from the migration package
The migration launcher SHALL select the packaged signed-out page, consent and device page bundles, API description and its policy, and subject-report catalog by default.

#### Scenario: Move the deployment directory
- **WHEN** the operator starts the launcher from a different working directory
- **THEN** resolve its default asset paths relative to the packaged binary

#### Scenario: Supply a deployment override
- **WHEN** the operator supplies an explicit asset setting
- **THEN** pass that setting through to the server
