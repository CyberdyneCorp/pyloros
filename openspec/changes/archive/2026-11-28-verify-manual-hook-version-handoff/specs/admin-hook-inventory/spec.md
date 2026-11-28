## ADDED Requirements

### Requirement: Preserve the component selected by an in-flight manual test
A v1 manual test that has dispatched a component SHALL finish using that component when another replica replaces the hook binding. A manual test started after the replacement commits SHALL execute the newly selected version.

#### Scenario: The replacement test returns first
- **WHEN** an operator changes the binding while the first worker is running and a second test completes on a peer before the first returns
- **THEN** return each component's own result and record each completed manual test's success flag in its audit entry

#### Scenario: Restore a previous component
- **WHEN** an operator selects a previously staged digest again and then repeats a manual test
- **THEN** the new test uses the restored component without requiring another upload
