## ADDED Requirements

### Requirement: Preserve login context order after privacy filtering
When dispatching a committed login event, the worker SHALL emit the permitted stored fields in source execution order, including when a different version enqueued the event.

#### Scenario: Login with personal fields enabled
- **WHEN** email, user agent and IP were queued and personal fields remain enabled at delivery
- **THEN** emit email, user agent, IP, event type and user ID in that order, retaining any stored null values

#### Scenario: Privacy changes while a login delivery is pending
- **WHEN** personal fields were withheld when the event was queued or the recipient disables them before execution
- **THEN** emit only event type followed by user ID
