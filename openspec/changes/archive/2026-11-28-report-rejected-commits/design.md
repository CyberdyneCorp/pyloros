## Decision

Wait for the database to confirm commit before issuing success. An explicit rejection establishes rollback. A connection loss while awaiting acknowledgement leaves the outcome uncertain and requires separate reconciliation.
