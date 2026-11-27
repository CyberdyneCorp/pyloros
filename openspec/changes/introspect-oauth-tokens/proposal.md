## Why

Resource servers use introspection to decide whether a presented credential still grants access. During migration either backend must be able to answer for tokens issued by either service.

## What Changes

Add the existing form-based introspection endpoint for authenticated service callers. Return current PostgreSQL account, client and authorization state alongside verified token fields.

## Impact

The endpoint reads token revocations, sessions, client registrations, users, organization memberships, entitlements and IAM data.
