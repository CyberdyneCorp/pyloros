## ADDED Requirements

### Requirement: Display a hook context using its source-compatible representation
The context display guest SHALL render the supplied object using source-compatible dictionary, list and scalar formatting. It SHALL preserve member insertion order, append a newline and return the first 10,000 Unicode scalar values of that output.

#### Scenario: Display a nested manual context
- **WHEN** a manual invocation supplies `{"z":true,"a":[null,"snow"]}`
- **THEN** the output is `{'z': True, 'a': [None, 'snow']}` followed by a newline

#### Scenario: Repeat an object member
- **WHEN** a manual request contains `{"b":0,"a":1,"b":2}`
- **THEN** the displayed dictionary starts with `'b': 2` followed by `'a': 1`

### Requirement: Preserve registration context order after privacy filtering
The registration delivery adapter SHALL supply the permitted fields in their source execution order for new and pending deliveries.

#### Scenario: Registration with personal fields
- **WHEN** the stored delivery includes email and address and the hook still permits personal fields
- **THEN** the component receives email, address, event type and user ID in that order

#### Scenario: Registration with personal fields withheld
- **WHEN** privacy filtering at enqueue or execution withholds personal fields
- **THEN** the component receives only event type followed by user ID
