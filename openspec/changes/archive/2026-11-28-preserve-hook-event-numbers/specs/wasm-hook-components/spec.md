## ADDED Requirements

### Requirement: Numeric range during component event admission
The offline fixture checker, artifact dry run and isolated worker SHALL admit otherwise valid bounded JSON events independently of the host floating-point range and forward the original numeric tokens to the component.

#### Scenario: Unrelated field contains a large number
- **WHEN** an admitted event contains a 400-digit integer alongside a string event name
- **THEN** a component that reads only the event name can execute and return that name

#### Scenario: Invalid event contains a large number
- **WHEN** an event containing a large number also contains malformed JSON or exceeds existing event limits
- **THEN** the host refuses the event before component execution
