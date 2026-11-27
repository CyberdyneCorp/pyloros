## ADDED Requirements

### Requirement: Deliver administrator entitlement changes
The service SHALL queue one delivery per matching active component hook for each committed administrator grant or withdrawal when operator entitlement dispatch is enabled.

#### Scenario: Personal or organization ownership
- **WHEN** a grant is issued or reactivated
- **THEN** deliver the entitlement id, product, plan, source and organization, with the subject user id for a personal grant and a null user id for an organization grant

#### Scenario: Repeated withdrawal
- **WHEN** an administrator withdraws an existing entitlement, including one already withdrawn
- **THEN** deliver a revocation with its subject, entitlement id, product and plan

#### Scenario: Change rolls back
- **WHEN** the grant, withdrawal or its administrator audit record cannot commit
- **THEN** leave no queued delivery for that operation
