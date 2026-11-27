## ADDED Requirements

### Requirement: Validate email challenge requests

The service SHALL decode UTF-8, UTF-16 and UTF-32 JSON for recipient actions and polling. Field errors SHALL identify the submitted value. Only validated requests SHALL consume the applicable quota.

#### Scenario: Invalid recipient token field

- **WHEN** the request omits the token or supplies an invalid type or length
- **THEN** return the field validation error before inspecting or changing a challenge.

#### Scenario: Status polling

- **WHEN** the initiating client polls with a well-formed credential field
- **THEN** apply the polling quota and verify the credential and its challenge binding.
