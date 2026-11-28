## Why

Clients can request another recovery email while the first request is still being processed. Operators also need to distinguish a refused email from an accepted email whose credential fails to commit.

## What Changes

Specify independent issuance for overlapping requests and the database effects of delivery and commit failures.

## Impact

Documents the existing password reset request endpoint.
