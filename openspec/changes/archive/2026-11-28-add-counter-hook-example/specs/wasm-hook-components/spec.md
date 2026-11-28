## ADDED Requirements

### Requirement: Run a numeric counter guest
The example counter guest SHALL accept a JSON object with a numeric field named n and output its value plus one followed by a newline. It SHALL preserve integer precision up to 4,300 decimal digits in both input and output and return a guest error for a missing or unsupported value.

#### Scenario: Increment a large decimal integer
- **WHEN** a valid integer exceeds the machine word size and its successor fits the decimal limit
- **THEN** return the exact decimal result

#### Scenario: Missing count
- **WHEN** the event object omits n
- **THEN** return the missing-key diagnostic
