# admin-analytics Specification

## Purpose
Define the account, registration, session activity and authentication-method reports available to administrators.

## Requirements

### Requirement: Read administrative analytics
Pyloros SHALL provide authenticated administrators with GET operations for overview, registrations, auth-methods and activity under /api/v1/admin/analytics.

#### Scenario: Overview requested
- **WHEN** an administrator reads the overview
- **THEN** the report includes user, registration, unrevoked session and hook counters

#### Scenario: Historical registrations requested
- **WHEN** an administrator requests a registration lookback of 1 through 365 days
- **THEN** the report includes populated calendar dates in ascending order and their total, with 30 days as the default

#### Scenario: Authentication methods requested
- **WHEN** an administrator reads authentication methods
- **THEN** the local password estimate appears first, followed by identity counts grouped by type and provider and the total of all entries

#### Scenario: Activity requested
- **WHEN** an administrator reads activity
- **THEN** the service reports distinct users with unrevoked session activity over 24 hours, 7 days and 30 days, plus the live session count and whole-second mean and median age

#### Scenario: Registrations span local midnight
- **WHEN** a deployment sets PYLOROS_REGISTRATION_TIME_ZONE to its reporting calendar
- **THEN** registrations are assigned to dates in that time zone while the lookback covers elapsed 24-hour periods
