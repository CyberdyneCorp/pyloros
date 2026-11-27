Use the configured account encryption key and the same wallet generator used during registration. Treat a nonempty stored address as an existing wallet, including on older accounts with incomplete key material. Return the user identifier, address and creation flag. Keep the wallet write and audit append in the same transaction.

A sequential retry returns the stored address. Overlapping first-time requests can each issue a keypair. The response describes that request's write. Each audit event identifies the operator and user and carries empty metadata. An existing-address lookup also works without access to the encryption key.

If the account disappears during the update, return the shared unhandled error document and roll back without an audit event.
