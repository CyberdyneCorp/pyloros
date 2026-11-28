## ADDED Requirements

### Requirement: Measure stored assignments under overlapping registered namespaces
The operator command SHALL optionally report aggregate counts of candidate PostgreSQL role groups, populated candidate groups, their membership rows and distinct member identities. A candidate group has a name beginning with `rp:`, the longer ID in an overlapping registered pair and a literal colon. The report SHALL include inactive registrations and read the counts from one committed snapshot.

#### Scenario: Multiple prefixes match one group
- **WHEN** a stored group name matches two overlapping registered namespaces
- **THEN** count that group once and count each of its memberships once

#### Scenario: Identity belongs to multiple candidate groups
- **WHEN** one identity has membership in two candidate groups
- **THEN** count both membership rows and one distinct identity

#### Scenario: No stored assignments
- **WHEN** candidate groups exist but all are empty
- **THEN** report their count with zero populated groups, membership rows and identities
