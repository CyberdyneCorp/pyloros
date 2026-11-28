## ADDED Requirements

### Requirement: Admit formatted manual component contexts
The v1 manual test SHALL pass an in-budget context to the guest verbatim. When the submitted context exceeds 65,536 UTF-8 bytes, the service SHALL remove insignificant JSON whitespace and apply the limit to the resulting bytes.

#### Scenario: Formatting exceeds the worker budget
- **WHEN** the context exceeds the budget but its JSON tokens fit
- **THEN** invoke the component with the compact context, preserving the exact tokens and their order

#### Scenario: Event data exceeds the worker budget
- **WHEN** the compact context still exceeds the limit
- **THEN** return the failed manual result, audit its failure and preserve automatic execution history
