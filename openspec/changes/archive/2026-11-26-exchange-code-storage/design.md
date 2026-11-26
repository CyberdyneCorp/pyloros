## Decisions

Generate an opaque random code, store its SHA-256 digest and keep the plain value only for the redirect. Read the row by digest and client. After the exchange use case validates it, claim the row and bind a new session ID in one conditional update. Session creation and token issuance must share the claim transaction. A competing exchange re-reads the winning session ID to apply replay policy.
