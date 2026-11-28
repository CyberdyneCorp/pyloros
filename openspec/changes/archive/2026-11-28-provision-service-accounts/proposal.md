## Why

Trusted service clients need to invite a person to establish an account with their own email address.

## What Changes

Add service-authorized account invitations and inbox confirmation through the existing password activation flow.

## Capabilities

### New Capabilities

- `service-provisioning` handles service-client invitations.

## Impact

Uses PostgreSQL account, client, token and audit records and the configured email provider.
