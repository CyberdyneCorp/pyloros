# Handing off role permission writes

During a gradual backend switch, both of these routes replace the same permission set for a client and role.

- `PUT /api/v1/admin/clients/{client_id}/roles/{role_key}/permissions`
- `PUT /api/v1/clients/me/roles/{role_key}/permissions`, with the client identified by its authenticated service token

A request can finish on the outgoing service while its PostgreSQL transaction is still open. If the incoming service replaces the same mapping during that interval, the writes can overlap. Use the following procedure when the deployment can control admission for both routes.

1. Hold new replacements on both routes for the affected client and role. If routing cannot identify the client on the delegated path, hold both routes for the handoff window. Keep track of the last submitted set.
2. Drain outstanding requests on the outgoing instances, including database work that continues after a response. Verify that their write transactions have completed on the PostgreSQL primary.
3. Read the mapping from the primary through the API and reconcile the permission set and its committed audit event with the last submitted write. A rolled-back write leaves the previous mapping in place. Resolve any discrepancy before releasing queued writes.
4. Route both paths to the incoming writer, release held requests in order, and verify the resulting mapping from the other backend. Use the same sequence when switching back.

## Local rehearsal

On a disposable PostgreSQL database, a deferred audit trigger held the outgoing replacement at commit. Each outgoing backend handled both operator and delegated writes. For each caller, one transaction committed and one rolled back. All eight trials began with `read`, requested `export`, and ended with a replacement of `list` from the new writer through the other route.

| Outgoing backend | While PostgreSQL held commit | After commit | After rollback |
|---|---|---|---|
| CyberdyneAuth | HTTP 200 for all four requests | Both APIs read `export` and the audit recorded the original caller | Both APIs read `read` and the attempted change had no committed audit event |
| Pyloros | All four requests waited | HTTP 200, with the same mapping and audit outcome | HTTP 500, with the same mapping and audit outcome |

In each trial both read APIs saw the previous mapping during the hold. After the handoff both saw `list`, with one committed event attributed to the incoming caller. Repeating the eight trials on a fresh database produced the same results. The driver controlled admission directly in these trials.

## Four-replica proxy rehearsal

A local Apache 2.4.67 reverse proxy routed requests to one of two backend pools. Each pool had two API processes connected to the same PostgreSQL primary. The proxy could independently pause the two mapping PUT routes and select the active pool. During the pause it returned HTTP 503 for replacement attempts. Clients using this approach must retain their intended changes for reconciliation and resubmission after the handoff.

Eight handoffs exercised both writer directions, both caller types, and both commit outcomes. The proxy kept the pause active through the pool switch and the readback of the outgoing transaction. Its upstream selection identified the replica for every admitted write.

| Check | Observed |
|---|---|
| Mapping PUTs attempted during the pause | All 32 received HTTP 503 at the proxy without reaching an API process. |
| Mapping GETs during the pause | All 64 returned the expected committed permission set. Both replicas in each selected pool served reads. |
| Unrelated PUTs during the pause | All 16 reached the active pool and returned the expected HTTP 401 for a request without credentials. |
| Setup, outgoing and incoming replacements | All 24 reached the intended pool, with writes observed on all four replicas. The final mapping and audit actor matched in all eight handoffs. |

The test used loopback traffic and a local admission rule. A production canary still needs to verify the deployed routing rules, every path to the writers, and how callers handle a paused replacement.

## Recovering a paused CLI edit

The installed `cyberauth 0.1.0` CLI made one PUT attempt and exited with code 7 when the proxy returned HTTP 503. This held for both the administrator and delegated service commands, in both handoff directions. The rejected attempt left the mapping and audit count unchanged.

Keep the full intended permission set. After the switch, use the corresponding `role-permissions get` command to read the current set. If another writer changed it, reconcile the edit before proceeding. Once writes resume, submit the reconciled set. In all four trials the original set command could be submitted unchanged. It made one PUT, returned the saved permissions, and added one audit event attributed to the expected user or service client. All four replicas then returned the saved set.

This recovery procedure covers a 503 generated by the admission rule before forwarding. A lost response after forwarding leaves the commit outcome uncertain and requires readback before deciding whether to replay.

## Recovering a paused admin console edit

If the console shows `HTTP 503` after a permission checkbox changes, reload the clients page, reopen the client’s permissions, and select the role again. The checkbox can still show the attempted edit after the error. Reopening the role reads the committed permissions. Once writes resume, apply the desired change from that fresh view and reopen the role to verify it.

Four Chromium trials exercised a grant and a revocation in each handoff direction, using the unchanged console with its origin allowed on both backends. During the pause each click sent one PUT. The console displayed the error and left the checkbox checked for a rejected grant or unchecked for a rejected revocation. All four API replicas continued to return the previous mapping, and the audit count stayed unchanged. After the switch, reopening the role showed the previous mapping. Each subsequent edit sent one successful PUT to the incoming pool, added one audit event, and remained visible after reloading.

## Existing permission catalogs above 256 keys

Both writers can list an existing catalog above 256 permissions. A request to create a duplicate returns HTTP 409 with the duplicate-key diagnostic. A new key also returns 409 while the catalog holds 256 or more entries.

In a local handoff rehearsal, both services read all 257 stored keys. Deleting one key left the catalog full. A second deletion brought the count to 255, and creating a retired key then succeeded. Both writers showed the recreated permission with its former role mappings removed. Reassign it explicitly if the role still needs it. The two deletions and one creation each had a committed audit entry attributed to their caller.
