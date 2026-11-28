## ADDED Requirements

### Requirement: Preserve independent grants across membership batches
The service SHALL evaluate all eligible membership batches within the decision budget. Revoking a grant in one batch SHALL preserve access through any remaining eligible grant in another batch.

#### Scenario: Withdraw overlapping grants
- **WHEN** an application withdraws membership from a team while another team still grants the same permission
- **THEN** new checks on both replicas allow access until the last granting membership is removed

#### Scenario: A partial final batch grants access
- **WHEN** full membership batches produce no grant and a team in the final partial batch grants the permission
- **THEN** allow access if that team's rule fits the remaining budget
