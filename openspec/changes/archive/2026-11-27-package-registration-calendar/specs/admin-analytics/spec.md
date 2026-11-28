## ADDED Requirements

### Requirement: Use the deployment registration calendar
The migration launcher SHALL accept an optional registration-time-zone file containing the reference PostgreSQL session’s time zone.

#### Scenario: Read a captured calendar
- **WHEN** a package includes the time zone and no explicit report setting is supplied
- **THEN** set PYLOROS_REGISTRATION_TIME_ZONE to the file value

#### Scenario: Override a packaged calendar
- **WHEN** the operator sets PYLOROS_REGISTRATION_TIME_ZONE
- **THEN** use the supplied setting in preference to the package value
