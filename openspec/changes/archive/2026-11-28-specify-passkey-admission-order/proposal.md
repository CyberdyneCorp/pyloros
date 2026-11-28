## Why

A browser can preflight a passkey sign-in or retry after a size error. Clients need to know whether either request spends their remaining login allowance.

## What Changes

Document how the login options endpoint handles preflight, oversized bodies and exhausted quota.

## Impact

Clarifies the existing passkey-management contract. No API or database changes are required.
