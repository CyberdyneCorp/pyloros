# Switching writers for existing account passwords

Self-service changes, administrator resets and email reset confirmations all replace the same stored account credential. During a pool switch, an admitted request can still be updating PostgreSQL while the incoming pool starts receiving traffic.

1. Pause new password replacements at ingress before forwarding them to either pool. Cover `POST /api/v1/auth/password/change`, `PUT /api/v1/admin/users/{user_id}/password` and `POST /api/v1/auth/password/reset-confirm`, including trailing-slash requests. Include any deployment-specific writers to the same accounts.
2. Keep the pause active while switching pools. Drain admitted requests on the outgoing replicas and confirm that their database transactions have finished on the primary. A password-change success audit identifies a committed change. Profile reads can continue during the pause.
3. For a canary account, sign in with its expected credential on the incoming pool and use that session for an authenticated read. Password changes advance the access-token cutoff. With revocation enforcement enabled, a token issued in the same second as the cutoff can be refused. In that case, sign in again after the cutoff second.
4. Reopen writes on the incoming pool. For a self-service change, use a fresh session and the currently committed password. For an administrator reset, use the authorized operator session. If a response was lost after forwarding, reconcile the committed operation before resubmission.

## Pending email resets

If ingress refused a reset confirmation before forwarding it, the account holder can submit the same unexpired link after writes reopen. An intervening self-service password change can leave an issued link usable. Once its redemption commits, submitting it again returns HTTP 400 on either backend.

In the local rehearsal, the outgoing pool issued a reset email and admitted a self-service password change. The proxy refused the emailed credential on both sides of the pool switch. After the change committed, the replacement password worked and the reset credential was still unused. The incoming pool then redeemed the link once and revoked the session opened with the intermediate password. Both pools accepted the final password. The rehearsal also covered an incoming self-service change and an administrator reset. Deployment routing and ordinary concurrent password changes have separate signoff gates.
