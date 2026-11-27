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
