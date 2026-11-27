## ADDED Requirements

### Requirement: Hook egress readiness
When hooks are enabled, readiness SHALL include a boolean indicating whether the service is running its hook egress proxy. Proxy availability SHALL be independent of the database readiness status.

#### Scenario: Listener cannot start
- **WHEN** the configured port is unavailable
- **THEN** readiness reports the proxy as unavailable and the auth service continues to handle requests

#### Scenario: Hooks disabled
- **WHEN** the operator disables hooks
- **THEN** readiness omits the proxy indicator and the service does not start a hook listener

#### Scenario: A hook requests network access
- **WHEN** the listener accepts a tunnel request
- **THEN** it permits only configured hosts and their subdomains on web ports and connects only to a verified public destination address

#### Scenario: A listener hostname resolves to multiple local addresses
- **WHEN** a required address is already bound
- **THEN** the proxy reports unavailable and releases any sockets it opened for the other addresses
