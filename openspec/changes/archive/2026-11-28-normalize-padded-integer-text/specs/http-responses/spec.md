## ADDED Requirements

### Requirement: Normalize leading zero padding in integer fields
Integer text fields SHALL recognize repeated underscore separators in leading zero padding and apply field bounds to the resulting value. Validation diagnostics SHALL retain the submitted input.

#### Scenario: Select a page with padding
- **WHEN** a page parameter contains 0__2
- **THEN** return the same page as the integer 2

#### Scenario: Normalized negative value is below the minimum
- **WHEN** a page parameter contains 0-_2
- **THEN** report the lower-bound error for the negative value

#### Scenario: Repeated separator between significant digits
- **WHEN** a page parameter contains 1__2
- **THEN** return an integer parsing error
