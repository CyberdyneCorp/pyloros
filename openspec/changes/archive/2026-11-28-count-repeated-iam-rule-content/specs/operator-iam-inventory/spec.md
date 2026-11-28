## ADDED Requirements

### Requirement: Count repeated stored IAM rule content
The read-only inventory SHALL optionally count chain-linked policies with repeated rule content, repeated groups of rules within those policies and excess rows. Equality SHALL compare SID, effect, actions, resources and conditions using their stored PostgreSQL values independently of row ID and position.

#### Scenario: Import renumbers duplicate rules
- **WHEN** two rules in the same chain-linked policy have identical stored content and different positions
- **THEN** the content inventory reports one affected policy, one repeated rule and one excess row

#### Scenario: Different identifiers or content
- **WHEN** two rules differ in SID, effect, actions, resources or conditions, or belong to different policies
- **THEN** they do not form a repeated group together
