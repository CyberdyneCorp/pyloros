## ADDED Requirements

### Requirement: Diagnose malformed UUID text regardless of length
A typed REST UUID field SHALL report the first invalid character and its one-based position in the submitted text, including when the UTF-8 input exceeds 45 bytes. If all characters within the recognized wrapper are hexadecimal digits or hyphens, the validator SHALL report the applicable simple length, group count or group length.

#### Scenario: Nested wrappers
- **WHEN** a lowercase UUID URN contains a braced UUID
- **THEN** the field error identifies the opening brace at position ten

#### Scenario: Extra groups in long input
- **WHEN** a hyphenated UUID field contains more than five groups and exceeds 45 bytes
- **THEN** report the submitted group count and the expected count of five
