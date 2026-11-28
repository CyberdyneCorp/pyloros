## ADDED Requirements

### Requirement: Preserve authentication event cursor interpretation
Both authentication history listings SHALL interpret supported alternative cursor encodings identically.

#### Scenario: Alternative hexadecimal event identifier
- **WHEN** a cursor’s identifier contains 32 characters after wrapper and hyphen removal and represents a hexadecimal integer with Unicode decimal digits, a leading plus sign or valid underscore separators
- **THEN** continue at the decoded timestamp and numeric identifier and audit the successful read

#### Scenario: Week date exceeds the calendar
- **WHEN** the ISO week date in a cursor resolves beyond Gregorian year 9999
- **THEN** return the invalid cursor error before recording a successful read
