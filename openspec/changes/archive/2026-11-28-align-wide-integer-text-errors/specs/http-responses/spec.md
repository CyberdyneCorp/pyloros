## ADDED Requirements

### Requirement: Classify wide integer text errors
Integer text validation SHALL report the size issue when the initial canonical signed decimal prefix exceeds 4,300 characters. If the integer requires normalization and the resulting signed decimal exceeds the same limit, the validator SHALL return the integer parsing issue. In-range representations SHALL continue to reach field-specific bounds checks.

#### Scenario: Negative integer at the signed boundary
- **WHEN** an integer field receives a minus sign followed by 4,300 digits starting with a nonzero digit
- **THEN** the issue type is int_parsing_size

#### Scenario: Explicit plus on an overlong integer
- **WHEN** an integer field receives a plus sign followed by 4,301 digits starting with a nonzero digit
- **THEN** the issue type is int_parsing and the input retains the submitted text
