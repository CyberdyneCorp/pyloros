## ADDED Requirements

### Requirement: Service account invitations

The service SHALL allow an active service client with the provisioning scope to invite a person by email, returning the same accepted response for new accounts, existing accounts and repeated requests within the address quota.

#### Scenario: Invite a new person

- **WHEN** a permitted service submits a new address
- **THEN** create an unverified passwordless account and send a time-limited activation link to the inbox. Store any submitted name as an unconfirmed hint.

#### Scenario: Invite an existing account

- **WHEN** an eligible invitation names an existing account
- **THEN** send an existing-account notice with a reset link and preserve its credentials and profile.

#### Scenario: Permission withdrawn

- **WHEN** the registration loses its provisioning scope after token issuance
- **THEN** refuse the request before account creation or email delivery.

#### Scenario: Suppress repeated delivery

- **WHEN** an accepted address is invited again within its delivery quota
- **THEN** record the throttled outcome without storing the address in the operator audit or sending another email.

#### Scenario: Registration hook requires an unavailable dispatcher

- **WHEN** the deployment enables an active registration hook while its dispatcher is unavailable
- **THEN** respond with HTTP 503 for both new and existing addresses before consuming the address quota or mutating account records.
