## Why

An emailed verification code can remain usable after PostgreSQL rejects its redemption at commit. Clients need a reliable response before treating the account as verified.

## What Changes

Specify the commit boundary for email confirmation and cover a retry after an explicit database rejection.

## Impact

Applies to the existing email confirmation endpoint and its account, membership, token and audit writes.
