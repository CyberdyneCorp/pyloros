Password sign-in carries its first-factor proof in the signed challenge. Passkey sign-in also claims a stored ceremony before verifying the second factor. The session transaction consumes the authenticator step or recovery code. Its rollback therefore preserves the second factor on both paths.

Test retry on the peer backend with shared signing keys, encryption settings and PostgreSQL storage. Inspect factor usage and session counts before rollback, after rollback and after successful retry.
