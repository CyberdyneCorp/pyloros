## ADDED Requirements

### Requirement: List the organization catalog

An operator SHALL be able to page through organizations ordered by name with a filtered total. The directory SHALL support filtering by active status, presence of a GitHub login or domain, and literal case-insensitive search across the name, short name, domain and GitHub login.

#### Scenario: Membership picker

- **WHEN** an operator asks for active organizations
- **THEN** return only active entries with their directory fields

#### Scenario: Page beyond the last match

- **WHEN** the requested page is empty
- **THEN** return an empty array and the total matching all filters
