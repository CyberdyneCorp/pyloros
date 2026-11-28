## ADDED Requirements

### Requirement: Versioned Unicode context display
Operators SHALL be able to build distinct context-display components using the Unicode 15.0 and 16.0 general categories. Both SHALL retain the same field order, quoting and output length rules.

#### Scenario: A character became printable after Unicode 15.0
- **WHEN** a context string contains U+1FAE9
- **THEN** the Unicode 15.0 component emits its escaped code point and the Unicode 16.0 component emits the character
