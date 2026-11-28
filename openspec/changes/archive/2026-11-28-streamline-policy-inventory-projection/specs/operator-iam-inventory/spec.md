## ADDED Requirements

### Requirement: Preserve policy directory shape across statement counts
The PostgreSQL policy directory SHALL include each policy in name order, including policies with no statements. Within each policy it SHALL present statements in stored sort order.

#### Scenario: Empty and populated policies share the directory
- **WHEN** an operator lists a directory containing empty and multi-statement policies
- **THEN** the empty policies contain empty statement arrays and the populated policies retain their statement identifiers, effects, actions, resources and conditions
