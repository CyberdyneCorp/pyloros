## ADDED Requirements

### Requirement: Complete password-bound MFA
The verification endpoint SHALL require a signed password-bound MFA credential and a valid enrolled factor before creating a session. The service SHALL audit unsuccessful checks and apply a per-source quota to validated requests.

#### Scenario: Complete password login
- **WHEN** the client presents a valid authenticator or recovery code
- **THEN** commit the factor claim, authenticated session and successful MFA audit together and return first-party tokens and cookies.

#### Scenario: Invalid factor or challenge
- **WHEN** the submitted factor or credential fails verification
- **THEN** return the corresponding authentication error without issuing credentials.
