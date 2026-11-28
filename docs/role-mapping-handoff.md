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

In each trial both read APIs saw the previous mapping during the hold. After the handoff both saw `list`, with one committed event attributed to the incoming caller. Repeating the eight trials on a fresh database produced the same results. The driver controlled admission directly. Deployment signoff still requires exercising the actual ingress and all writer replicas.
