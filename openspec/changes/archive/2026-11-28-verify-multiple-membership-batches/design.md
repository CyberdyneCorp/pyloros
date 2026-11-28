## Decisions

Exercise one folder linked to 65 teams, with assignments at the start of each 32-object traversal group. Use two clients and two accounts with overlapping application object IDs. Check both API replicas after each acknowledged change.

## Verification

Check the traversal budget on both sides of a batch boundary. Verify access persists until the last path is removed and reconcile committed audit entries with writes.
