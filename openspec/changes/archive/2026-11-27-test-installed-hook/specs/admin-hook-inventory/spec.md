## ADDED Requirements

### Requirement: Test an installed hook
The service SHALL let an authorized operator run the component selected for an installed hook against a supplied context and report success, output, error and elapsed milliseconds.

#### Scenario: Test a disabled definition
- **WHEN** an administrator tests a disabled hook with a selected component
- **THEN** execute that component once using the supplied context and the configured timeout

#### Scenario: Omit the context
- **WHEN** an administrator sends an empty request object or an explicit null context
- **THEN** pass an empty object to the component

#### Scenario: Record the outcome
- **WHEN** the component completes successfully or returns a handler error
- **THEN** return the outcome, record the success flag in the operator audit and preserve automated delivery history

#### Scenario: Missing component selection
- **WHEN** a definition has no selected component
- **THEN** report that execution is unavailable and preserve its execution history

#### Scenario: Exceed the execution deadline
- **WHEN** the worker exceeds the timeout stored on the hook
- **THEN** terminate the worker and return a failed outcome with elapsed time

#### Scenario: Unavailable worker
- **WHEN** the worker cannot start or its execution slots are occupied
- **THEN** return a service unavailable response and preserve the audit and execution history
