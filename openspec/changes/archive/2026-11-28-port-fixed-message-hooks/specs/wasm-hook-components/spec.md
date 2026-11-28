## ADDED Requirements

### Requirement: Run a fixed-message guest
The fixed-message example SHALL return the build-time message followed by a newline, limited to 10,000 Unicode scalar values including the newline.

#### Scenario: Execute with unrelated context
- **WHEN** the worker passes an event to the component
- **THEN** the guest emits the configured output independently of the event data

#### Scenario: Message fills the output limit
- **WHEN** the message contains at least 10,000 Unicode scalar values
- **THEN** return its first 10,000 scalar values
