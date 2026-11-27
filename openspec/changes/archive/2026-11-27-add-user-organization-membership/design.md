Validate the operator and request, then check the account and active organization in that order. Store an explicit membership using the existing uniqueness constraint. Commit the operator audit in the same transaction.

Check for a committed membership before inserting. A repeated request records its own audit. If two first-time requests observe an absent row, let the unique constraint decide which transaction commits.
