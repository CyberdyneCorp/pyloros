Both endpoints operate on the outbox. A test creates one event and one delivery. A retry updates the existing delivery. Each operation writes its administrative audit record in the same transaction.

The redelivery response describes the queued delivery. History reads resolve the event type and prior attempts separately. When a deferred audit constraint rejects the commit, both operations roll back. Pyloros returns HTTP 500. Compatibility signoff for this case remains open.
