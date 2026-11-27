## Decisions

Use the signer and contract addresses from the same configuration snapshot. Resolve the policy identifier and encode the operation before submitting. Coordinate nonce allocation for concurrent submissions from the same signer. Verify the receipt before reporting success. Preserve the distinction between submission, confirmation and audit failures.

A database rollback cannot undo a confirmed external mutation. Compare the recorded outcome when audit persistence fails after the provider confirms a transaction. Avoid automatically resubmitting a mutation after an uncertain outcome.

## Verification

Compare unsigned call data and identifier handling using independent fixtures. Exercise concurrent submission, an unavailable provider, a rejected transaction, a reverted receipt, a confirmation timeout and audit failure. Verify the API and unchanged clients using an isolated provider.
