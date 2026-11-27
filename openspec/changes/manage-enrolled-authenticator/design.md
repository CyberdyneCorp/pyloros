## Decisions

Use the calling session for passwordless proof. Check session ownership, revocation and expiry before accepting either recent qualifying sign-in evidence or a session-bound proof from an active passkey. For an account with a password, verify the stored hash using the configured password verifier.

Serialize updates to an enrollment and consume each authenticator step once. Commit the recovery-code changes and success audit in the same transaction. Keep failed proof attempts auditable without changing the enrollment or consuming a valid step.
