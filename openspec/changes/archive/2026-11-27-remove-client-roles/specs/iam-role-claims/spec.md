## ADDED Requirements

### Requirement: Recognize stored organization role identifiers

The role group reader SHALL recognize a stored organization UUID whose hexadecimal digits have noncanonical hyphen placement.

#### Scenario: Existing organization assignment

- **WHEN** the group suffix contains all 32 UUID digits with an irregular hyphen position
- **THEN** the assignment resolves to the corresponding organization and can be removed through role administration
