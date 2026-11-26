## ADDED Requirements

### Requirement: Periodic email confirmation on password login
The service SHALL require email confirmation when the policy interval is set and the account has never confirmed or the interval has elapsed. A required confirmation SHALL create a pending challenge with a random email link, a two-digit match code, and a separate browser polling credential bound to the challenge. The service SHALL store only the link digest.

#### Scenario: Recent confirmation
- **WHEN** a password login occurs before the next confirmation is due
- **THEN** the workflow continues without creating a challenge or sending email

#### Scenario: Delivery failure
- **WHEN** the mail transport cannot send a required confirmation
- **THEN** the workflow refuses login, rolls back the pending challenge, and records the delivery failure
