## Decisions

Use the signer and contract addresses from the same configuration snapshot. Resolve the policy identifier and encode the operation before submitting. Coordinate nonce allocation for concurrent submissions from the same signer. Verify the receipt before reporting success. Preserve the distinction between submission, confirmation and audit failures.

A database rollback cannot undo a confirmed external mutation. Compare the recorded outcome when audit persistence fails after the provider confirms a transaction. Avoid automatically resubmitting a mutation after an uncertain outcome.

## Verification

Compare unsigned call data and identifier handling using independent fixtures. Exercise concurrent submission, an unavailable provider, a rejected transaction, a reverted receipt, a confirmation timeout and audit failure. Verify the API and unchanged clients using an isolated provider.

## Open compatibility decisions

Determine the response and audit outcome for a receipt with an absent or nonstandard status, a hash that differs from the submitted transaction, or a confirmed creation whose identifier cannot be decoded. Verify against the deployment contract before enabling retries or marking chain creation compatible.

## Receipt inspection during reconciliation

Run `just inspect-iam-receipt HASH` with `BLOCKCHAIN_RPC_ENDPOINT` pointing at the intended chain. The command reads the receipt for that hash without a signer or a database connection. A matching transaction hash with status `0x1` reports `reported_success` and exits zero. A reverted, absent, mismatched or unrecognized receipt produces a distinct observation and exits 2. Invalid input or an RPC failure exits 1. This inspects the provider's reported execution status. Block finality, contract address, creation events and audit persistence require separate verification.

## Unsigned payload

Preparation produces the type-2 transaction prefix followed by the RLP list of chain ID, pending nonce, priority fee, maximum fee, gas limit, destination, zero value, call data and an empty access list. Preserve full-width quantities from the provider. The sender address selects the pending nonce and gas estimate and is excluded from the signing payload.

With `--wait`, poll while the receipt is absent. Apply a single 60-second deadline across provider calls, transport retries and polling delays. Return immediately when the provider supplies a receipt or rejects the read. A timeout leaves the transaction outcome unresolved.
