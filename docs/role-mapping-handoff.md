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

## Global role capacity

The PostgreSQL catalog limit is 64 global roles per client. In two handoff trials, a client started with 65 global roles and 1,000 organization-scoped groups. The administrator and delegated APIs listed all 65 global roles with the same member counts on both services. Removing one global role left the catalog full. After a second removal, recreating a retired role succeeded with zero members and an empty permission mapping.

On this fixture, PostgreSQL query plans showed 65 executions of the inventory's membership count after filtering scoped groups, down from 1,065. This measures database work for the catalog read.

## Switching writers at the final catalog slot

The operator and delegated creation routes share a client's catalog. When the role or permission catalog has one slot left, requests admitted by different writers can compete for it.

1. Hold creation at ingress for both `POST /api/v1/admin/clients/{client_id}/{roles|permissions}` and `POST /api/v1/clients/me/{roles|permissions}`. Keep inventory reads available. The local rehearsal held all four creation paths across clients for the handoff window.
2. Drain already admitted writes on the outgoing pool and confirm their PostgreSQL transactions have ended. Read the catalog and its committed creation audit on the primary. If a read disconnects or receives a proxy error, repeat the read before deciding whether a slot is free.
3. Keep admission closed through the pool switch. Verify the committed key and count through the incoming pool, then release admission. If the last slot is occupied, a different key receives HTTP 409. If the outgoing transaction rolled back, the incoming writer can create a key in the free slot.

Eight local handoffs covered the 64th role and 256th permission in both writer directions. A committed creation occupied the final slot in every case. On an injected commit rejection, the reference returned HTTP 201 and Pyloros returned HTTP 500. Both left the slot free with no creation audit. Each incoming writer then created a different key and recorded its caller. Two preliminary rollback trials encountered a disconnect or HTTP 502 on inventory readback. Deployment ingress still requires verification.

## Concurrent creation after the switch

For a canary that assigns catalog creation to Pyloros, route both the operator and delegated role and permission POSTs to the Rust pool. An administrator and a service client can compete for the same slot through different URLs. Inventory reads and deletion can continue through the reference pool.

In the local four-replica rehearsal, two distinct keys competed for the last slot. With both creates routed to Pyloros, one returned HTTP 201 and the other returned HTTP 409. Both reference replicas saw the committed winner and the catalog contained exactly 64 roles or 256 permissions. The audit identified the winning caller. While both requests waited for the target client's database lock, a create for another client completed.

With both creates routed to reference replicas and both transactions held before insertion, both returned HTTP 201. The resulting catalogs contained 65 roles or 257 permissions and recorded both callers. This concurrency difference remains a migration signoff decision.

## Recovering a user role grant or revocation

An operator or delegated service can grant or revoke the same user's client role. If a response arrives while the outgoing transaction is finishing, hold further writes to that assignment until the database outcome is known. Check the role on the primary through `GET /api/v1/admin/users/{user_id}/roles`. For a scoped assignment, check the entry for the intended organization.

Also reconcile the grant or revocation audit for the target, client, role and caller. A repeated grant can leave the same membership in place and still produce another audit entry and webhook event. When webhooks are enabled, check the stored event and delivery records for the subscriptions that matched at write time. A receiver can acknowledge delivery later.

With two active subscribers on a disposable PostgreSQL database, an injected delivery insertion failure rolled back the role change, audit and webhook records together. Both APIs returned HTTP 500 on an immediate failure. When PostgreSQL rejected the insert at commit, Pyloros returned HTTP 500 and the reference API returned HTTP 201 for a grant or HTTP 204 for a revocation. This held for both operators and delegated clients.

After confirming rollback, retry the intended change once on the incoming writer and read the assignment again. In the rehearsal each retry committed the intended membership state, one audit entry, one event and two deliveries.

## Reconciling a chain-backed assignment

For chain-backed roles, check membership on the configured group contract before acting on a disputed grant or revocation. Resolve the client role's group ID and the user's linked identity token ID. For an organization-scoped assignment, use the organization-specific group. Read `getMembers(groupId)` and check for that identity token ID. Record the chain, contract and block used for the read so the result can be checked again.

In a loopback migration rehearsal, the provider rejected gas estimation before submission. The existing-group cases covered operator and delegated grants and revocations, both globally and within an organization. The observed API and PostgreSQL results were:

| Attempt | Reference API | Pyloros |
| --- | --- | --- |
| Grant into an existing group | HTTP 201, one grant audit and one queued webhook delivery | HTTP 502 for a contract rejection or 503 for a provider refusal, with no grant audit or delivery |
| Revoke from an existing group | HTTP 204, one revocation audit and one queued webhook delivery | HTTP 502 or 503, with no revocation audit or delivery |
| Grant requiring creation of an organization group | HTTP 500, with no grant audit or delivery | HTTP 500, with no grant audit or delivery |

Each trial had one matching webhook subscriber. A success audit and a queued notification can therefore accompany a failed reference write. If the membership read still shows the previous state, reconcile any downstream action taken on that notification before retrying. For a write that reached submission, use its transaction hash and the receipt inspection procedure as well.

Set `BLOCKCHAIN_RPC_ENDPOINT` to the provider for the intended chain, then run:

```sh
just inspect-iam-membership "$group_contract" "$group_id" "$identity_token_id" "$block_hash"
```

Supply the group and identity token IDs as unsigned decimal integers and the block as a 32-byte hash. The provider must support a canonical block hash on `eth_call` and have the state for that block. The command prints JSON containing the contract, block hash, IDs and `member`. Both membership outcomes exit successfully. A command or provider error exits nonzero without a report. The observation describes membership at the selected block. To check a later state, run the command again with its block hash.
