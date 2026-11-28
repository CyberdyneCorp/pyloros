# Switching writers for login session refresh and revocation

A refresh can rotate a credential while an administrator is trying to end the same session. During a pool switch, finish the admitted operation on the outgoing writer before admitting the next one on the incoming writer.

1. Hold new requests on `POST /api/v1/auth/refresh`, `DELETE /api/v1/admin/sessions/{session_id}` and refresh grants on `POST /api/v1/auth/oauth2/token`. If ingress routes by method and path alone, holding the entire OAuth token route also pauses other grants. Include every entry point to these writers in the deployment. Account for other operations that can end the affected sessions.
2. Drain requests already admitted to the outgoing pool and confirm that their database transactions have finished on the primary. Keep the hold active while switching upstreams. Session inventory reads can remain available.
3. Reconcile the expected committed state. A rotated session in this rehearsal had one active refresh record. A revoked session had a revocation timestamp, zero active refresh records and a committed administrator audit entry. If a revocation response was lost, read back its outcome before submitting it again. A repeated revocation can add another audit entry.
4. Reopen admission on the incoming pool. A caller whose refresh was refused at ingress before forwarding can retry with the credential it still holds. After a committed rotation, use the replacement credential. After revocation, ordinary login refresh returns HTTP 401. An OAuth refresh grant on the token endpoint returns HTTP 400 with `invalid_grant`.

## Rehearsal

A local reverse proxy selected between two pools of two API processes sharing PostgreSQL. Each trial held a session row in a separate transaction and confirmed that the admitted request was waiting on that transaction. With admission closed, the proxy returned HTTP 503 before forwarding fresh requests on all three paths. Session inventory remained readable. The hold stayed active through the switch.

In each direction we drained an ordinary login refresh and revoked the rotated session on the incoming writer. We also drained an administrator revocation and tried the existing credential on the incoming writer. Every session ended with zero active refresh records and one revocation audit.

### OAuth refresh grants

Eight additional handoffs exercised the OAuth token endpoint with public clients and confidential clients using HTTP Basic authentication. Each client obtained a resource-bound authorization code with PKCE and requested offline access. Each client type exercised both writer directions and both outgoing operations.

When refresh completed on the outgoing writer, the incoming writer rotated the replacement successfully. The three refresh records formed one chain with one active credential. All three retained the same client, resource and scopes. After administrator revocation, submitting the latest credential returned HTTP 400 with `invalid_grant`. When revocation completed before the switch, the incoming writer refused the credential with the same error. All eight sessions ended with zero active refresh records and one administrator revocation audit entry.

Deployment routing, additional session writers and steady-state concurrent writes require separate verification.
