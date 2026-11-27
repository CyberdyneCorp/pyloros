## ADDED Requirements

### Requirement: Validate account email domains

The service SHALL reject address literals, reserved public suffixes, invalid ASCII domain characters, and domains exceeding DNS size limits. The service SHALL evaluate an internationalized domain using its encoded DNS spelling.

#### Scenario: Invalid characters in a domain

- **WHEN** the domain contains several disallowed ASCII punctuation characters
- **THEN** report a field validation error identifying the distinct invalid characters in sorted order.

#### Scenario: Label exceeds its DNS length

- **WHEN** a client submits an ASCII domain label longer than 63 characters
- **THEN** identify the length excess before account lookup.

#### Scenario: Numeric end of an ASCII suffix

- **WHEN** the top-level domain ends in an ASCII digit and is not an internationalized label
- **THEN** reject the address before the recovery quota is spent.
