# admin-hook-inventory Specification

## Purpose
Let administrators inspect stored hook configuration and execution outcomes during and after a backend migration.

## Requirements

### Requirement: Inspect installed hooks and recorded runs
The service SHALL allow administrators to read installed hook definitions and the recorded executions associated with a hook.

#### Scenario: Inspect a disabled hook
- **WHEN** an administrator retrieves an inactive hook
- **THEN** return its saved definition, execution settings and privacy preference

#### Scenario: Page execution history
- **WHEN** an administrator requests a page of historical executions
- **THEN** return the latest runs first with the total count across pages

#### Scenario: Remove administrative access
- **WHEN** an operator loses administrator privileges
- **THEN** subsequent reads using the existing session are denied

### Requirement: Validate operator hook source
The service SHALL accept source validation requests from authorized administrators and report the applicable syntax or restricted-language diagnostic without executing the source.

#### Scenario: Valid source
- **WHEN** submitted source satisfies the authoring rules
- **THEN** return a positive validation result and an empty diagnostic

#### Scenario: Rejected source
- **WHEN** parsing or an authoring restriction rejects source
- **THEN** return a negative validation result with the diagnostic and preserve stored hooks and bindings

#### Scenario: Compiler context error
- **WHEN** a parsed module would fail during compilation because of an invalid declaration or control-flow context
- **THEN** report an internal server error without executing the module

#### Scenario: Worker unavailable
- **WHEN** the source-validation worker cannot accept or complete a request
- **THEN** return a service unavailable response and preserve stored hooks

#### Scenario: Source admission limits
- **WHEN** the HTTP envelope exceeds 64 MiB
- **THEN** return HTTP 413 before invoking the worker

#### Scenario: Large module
- **WHEN** an authorized operator submits a valid module larger than 2 MiB within the accepted request envelope
- **THEN** validate the entire module and return the result

### Requirement: Author hook definitions
The service SHALL accept authorized creation and editing of hook definitions, validate submitted source without executing it, and record each successful operation in the audit history.

#### Scenario: Create a definition
- **WHEN** an operator supplies an available name, supported event and acceptable source
- **THEN** return the persisted definition with its identifier and execution settings

#### Scenario: Partially edit a definition
- **WHEN** an operator updates selected settings on an existing hook
- **THEN** apply supplied non-null fields and preserve the other settings

#### Scenario: Reject invalid input
- **WHEN** an input violates the field schema, the source policy or name uniqueness
- **THEN** return the applicable validation or conflict response and preserve the stored definition

#### Scenario: Audit failure
- **WHEN** recording the operator action fails
- **THEN** roll back the mutation and preserve the previous component selection

#### Scenario: Concurrent creation with the same name
- **WHEN** two requests both observe that a name is available and attempt to insert it
- **THEN** commit one definition and audit entry, and return an internal error for the failed insertion

#### Scenario: Large authoring envelope
- **WHEN** a create or edit request contains extra JSON whitespace or a multibyte encoding
- **THEN** apply authentication and decoded field validation as for a compact request

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

### Requirement: Report hook binding coverage
A database operator SHALL be able to inspect all hooks and their selected component digests from a single read-only snapshot without starting the service or executing hooks. The report SHALL identify hooks by ID, name and event, include active state and the SHA-256 of UTF-8 source, and omit source text.

#### Scenario: Inventory before the binding migration
- **WHEN** the hook definitions exist and the binding table has yet to be installed
- **THEN** every hook is reported with a null component selection

#### Scenario: Determine active binding coverage
- **WHEN** an operator runs the check on a readable database
- **THEN** print a JSON report ordered by hook ID with the number of active unbound hooks and exit with code 2 if any exist, otherwise 0

#### Scenario: Inventory cannot be read
- **WHEN** required definitions or read access are missing
- **THEN** exit with an error distinct from incomplete coverage and emit no success report

### Requirement: Report the stored settings for each hook port
The read-only binding inventory SHALL include the stored timeout in seconds, network permission and personal data opt-in for each hook.

#### Scenario: Review selected and unselected hooks
- **WHEN** the operator checks binding coverage
- **THEN** each row includes its timeout_seconds, allow_network and receive_pii values alongside its digests

#### Scenario: Read a historical schema
- **WHEN** the hooks table lacks one or more settings columns
- **THEN** return null for each missing setting and retain the values of the available settings

### Requirement: Check component binding coverage for one event
The operator SHALL be able to limit the read-only inventory and its coverage exit code to a single supported hook event.

#### Scenario: Check a producer before switching it
- **WHEN** the operator supplies a supported event name to the binding check
- **THEN** report only definitions for that event, in hook ID order, and count only its active unbound definitions
- **AND** return success for a supported event with no definitions

#### Scenario: Mistyped event name
- **WHEN** the operator supplies an unknown event or malformed arguments to the binding check
- **THEN** exit with a usage error distinct from incomplete binding coverage and emit no inventory

### Requirement: Admit formatted manual component contexts
The v1 manual test SHALL pass an in-budget context to the guest verbatim. When the submitted context exceeds 65,536 UTF-8 bytes, the service SHALL remove insignificant JSON whitespace and apply the limit to the resulting bytes.

#### Scenario: Formatting exceeds the worker budget
- **WHEN** the context exceeds the budget but its JSON tokens fit
- **THEN** invoke the component with the compact context, preserving the exact tokens and their order

#### Scenario: Event data exceeds the worker budget
- **WHEN** the compact context still exceeds the limit
- **THEN** return the failed manual result, audit its failure and preserve automatic execution history

### Requirement: Inspect related hook events together
The binding inventory SHALL accept multiple supported event names and report all matching definitions in hook ID order from one read-only PostgreSQL snapshot. Its exit code SHALL reflect active unbound definitions among the selected events.

#### Scenario: Check both entitlement transitions
- **WHEN** the operator selects grant and revoke events and an active revoke hook lacks a binding
- **THEN** report incomplete coverage even when all active grant hooks are bound
- **AND** omit unrelated events and include each matching definition once even if an event argument repeats

#### Scenario: Unknown name in a combined check
- **WHEN** any supplied name is unknown
- **THEN** return a usage error without emitting a partial inventory

### Requirement: Verify a reviewed binding inventory
The project SHALL provide a local command to verify coverage and compare the generated inventory with a previously reviewed report for the same event selection. It SHALL fail if the inventory command fails, an active selected hook is unbound, or the report bytes differ.

#### Scenario: A fully bound hook selects a different component
- **WHEN** coverage succeeds but a selected component digest has changed since review
- **THEN** verification exits unsuccessfully

#### Scenario: A matching report contains an unbound active hook
- **WHEN** an inventory with missing active bindings exactly matches the saved file
- **THEN** verification exits unsuccessfully

### Requirement: Validate yield expressions in comprehension scopes
The source validator SHALL report a compiler context error for a permitted yield expression directly in the implicit scope of a comprehension. It SHALL evaluate the first iterable in the enclosing scope and a nested lambda body in its own function scope.

#### Scenario: Yield in a comprehension result
- **WHEN** an operator validates a function with a parenthesized yield as the result expression of a list comprehension
- **THEN** return HTTP 500

#### Scenario: Yield supplies the first iterable
- **WHEN** an operator validates a function with a yield supplying the first iterable of an otherwise valid comprehension
- **THEN** return a positive validation result

#### Scenario: Generator contains an unparenthesized yield result
- **WHEN** a function contains a generator expression beginning with a bare yield followed by a comprehension clause
- **THEN** report invalid syntax in the HTTP 200 validation result

### Requirement: Preserve the component selected by an in-flight manual test
A v1 manual test that has dispatched a component SHALL finish using that component when another replica replaces the hook binding. A manual test started after the replacement commits SHALL execute the newly selected version.

#### Scenario: The replacement test returns first
- **WHEN** an operator changes the binding while the first worker is running and a second test completes on a peer before the first returns
- **THEN** return each component's own result and record each completed manual test's success flag in its audit entry

#### Scenario: Restore a previous component
- **WHEN** an operator selects a previously staged digest again and then repeats a manual test
- **THEN** the new test uses the restored component without requiring another upload
