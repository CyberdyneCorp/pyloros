# project-usage Specification

## Purpose
Define how administrators review account access and sign-in activity by project or by user.

## Requirements

### Requirement: Report project usage
Pyloros SHALL restrict project usage reports to administrators and include access through active user entitlements or completed sign-ins.

#### Scenario: Review the project registry
- **WHEN** an administrator requests the project overview
- **THEN** return a paginated registry including disabled projects, distinct users, users with a sign-in in the last 30 days, entitled users and latest activity

#### Scenario: Inspect project members
- **WHEN** an administrator opens a registered project's user list
- **THEN** paginate distinct accounts with their email, current grant and completed sign-in count and time

#### Scenario: Inspect account usage
- **WHEN** an administrator opens an existing account's projects
- **THEN** list projects by case-insensitive name with grant and sign-in history, using the project identifier when the registry has no name for that project
