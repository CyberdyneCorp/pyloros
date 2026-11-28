## ADDED Requirements

### Requirement: Resolve historical checkout account identifiers
For a signed grant event with an explicit account reference, the service SHALL recognize legacy UUID spellings before checking the account and its customer mapping.

#### Scenario: Historical spelling identifies an existing account
- **WHEN** the reference uses compact hex inside braces, nonstandard hyphen placement, a lowercase UUID URN with compact hex, or Unicode decimal digits in the hex value
- **THEN** resolve the same account as the canonical UUID and apply the ordinary grant and replay rules

#### Scenario: Invalid explicit subject
- **WHEN** the explicit reference uses an uppercase URN scheme, is truncated, or contains a non-hexadecimal letter
- **THEN** defer the event as an unmapped customer and leave ownership and entitlements unchanged
