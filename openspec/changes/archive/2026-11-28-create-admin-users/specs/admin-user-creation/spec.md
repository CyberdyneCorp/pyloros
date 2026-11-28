## ADDED Requirements

### Requirement: Create a verified password account

The service SHALL accept authorized administrative user creation and return the new account identifier, normalized email, public key and wallet address.

#### Scenario: Provision an account

- **WHEN** an operator submits a valid unused email and password
- **THEN** create an active verified account with an encrypted managed wallet, record the operator and affected account, and apply registration integrations.

#### Scenario: Competing registrations

- **WHEN** competing requests attempt to provision the same normalized email
- **THEN** commit one account and return a conflict to the losing caller.

#### Scenario: Failed audit

- **WHEN** either required audit record cannot commit
- **THEN** roll back the account and any queued deliveries.

#### Scenario: Provision during a partial registration hook migration

- **WHEN** an operator creates an account while an active registration hook lacks a component binding
- **THEN** return HTTP 503 and roll back the account, creation audit and all registration hook deliveries, including deliveries for already bound hooks.

#### Scenario: Provision with all active hooks bound

- **WHEN** a new account is created with the registration dispatcher enabled and all active registration hooks bound
- **THEN** make the verified account available for login and dispatch each matching hook for the created account.
- **AND** a duplicate creation on the other backend returns a conflict and preserves the number of hook executions.
