## ADDED Requirements

### Requirement: Map optional provider profile strings
The Google adapter SHALL read email, name and picture from their corresponding profile fields. The Microsoft adapter SHALL use a nonempty mail value or fall back to userPrincipalName, read displayName for the name and leave the picture absent. A missing or null optional string SHALL remain absent unless the provider mapping supplies a fallback.

#### Scenario: Microsoft supplies a principal name
- **WHEN** the mail field is empty and a principal name is present
- **THEN** use the principal name as the candidate email and determine email verification independently

#### Scenario: Google omits display fields
- **WHEN** a Google profile contains a subject but omits name and picture
- **THEN** preserve the subject and leave the display fields absent
