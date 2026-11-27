## ADDED Requirements

### Requirement: Validate operator hook source
The service SHALL accept source validation requests from authorized administrators and report the applicable syntax or restricted-language diagnostic without executing the source.

#### Scenario: Valid source
- **WHEN** submitted source satisfies the authoring rules
- **THEN** return a positive validation result and an empty diagnostic

#### Scenario: Rejected source
- **WHEN** parsing or an authoring restriction rejects source
- **THEN** return a negative validation result with the diagnostic and preserve stored hooks and bindings
