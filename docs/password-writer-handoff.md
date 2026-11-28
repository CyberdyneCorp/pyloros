# Switching writers for existing account passwords

Self-service changes, administrator resets and email reset confirmations all replace the same stored account credential. During a pool switch, an admitted request can still be updating PostgreSQL while the incoming pool starts receiving traffic.

1. Pause new password replacements at ingress before forwarding them to either pool. Cover `POST /api/v1/auth/password/change`, `PUT /api/v1/admin/users/{user_id}/password` and `POST /api/v1/auth/password/reset-confirm`, including trailing-slash requests. Include any deployment-specific writers to the same accounts.
2. Keep the pause active while switching pools. Drain admitted requests on the outgoing replicas and confirm that their database transactions have finished on the primary. A password-change success audit identifies a committed change. Profile reads can continue during the pause.
3. For a canary account, sign in with its expected credential on the incoming pool and use that session for an authenticated read. Password changes advance the access-token cutoff. With revocation enforcement enabled, a token issued in the same second as the cutoff can be refused. In that case, sign in again after the cutoff second.
4. Reopen writes on the incoming pool. For a self-service change, use a fresh session and the currently committed password. For an administrator reset, use the authorized operator session. If a response was lost after forwarding, reconcile the committed operation before resubmission.

The local rehearsal covered an outgoing self-service change followed by either a self-service change or an administrator reset. Email reset confirmation was checked for ingress refusal during the pause. Deployment routing and ordinary concurrent password changes have separate signoff gates.
