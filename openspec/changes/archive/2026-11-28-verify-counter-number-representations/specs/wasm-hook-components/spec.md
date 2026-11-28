## ADDED Requirements

### Requirement: Preserve the numeric form in counter results
For finite numeric inputs within the supported range, the counter guest SHALL increment integer tokens using decimal integer arithmetic and tokens containing a fraction or exponent using binary64 arithmetic. Its output SHALL preserve the floating-point representation of integral floating-point results.

#### Scenario: Increment at the binary64 precision boundary
- **WHEN** n is 9007199254740992
- **THEN** the output line is 9007199254740993
- **WHEN** n is 9007199254740992.0
- **THEN** the output line is 9007199254740992.0

#### Scenario: Input uses exponent notation
- **WHEN** n is 1e16
- **THEN** the output line is 1e+16
