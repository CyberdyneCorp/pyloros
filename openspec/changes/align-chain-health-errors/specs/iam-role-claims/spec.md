## MODIFIED Requirements

### Requirement: Administrator chain health read

The service SHALL allow an authenticated administrator to check whether the selected chain provider can answer a block-number request. The response SHALL report enablement, availability, endpoint, identity contract address and any provider error. A configured runtime provider takes precedence over the deployment provider. The check SHALL complete within five seconds of starting the RPC operation.

#### Scenario: No configured provider

- **WHEN** no chain provider is configured
- **THEN** the check reports disabled and unavailable with null endpoint and contract address

#### Scenario: Recovery

- **WHEN** the provider answers successfully after an earlier RPC error
- **THEN** the next health read reports available and clears the error

#### Scenario: Provider request fails

- **WHEN** the block-number request encounters a transport failure
- **THEN** retry within the overall health deadline and report the failure detail if the provider remains unavailable

#### Scenario: Malformed provider response

- **WHEN** the provider returns malformed JSON
- **THEN** report the parse diagnostic and keep the selected endpoint and contract in the health response

#### Scenario: Health provider response identifier

- **WHEN** the provider answers the informational block-number request with a numeric response identifier or its decimal string representation
- **THEN** determine availability from its response and report malformed envelopes with a diagnostic

#### Scenario: Large successful reply

- **WHEN** a valid block-number response includes large extension fields
- **THEN** report availability from the block result within the health deadline
