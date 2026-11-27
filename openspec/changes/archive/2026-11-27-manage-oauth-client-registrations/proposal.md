## Why

Operators need to provision and maintain applications from the same admin console and CLI while both backends serve traffic.

## What Changes

Implement administrative creation, partial update, secret rotation and deactivation of shared OAuth clients.

## Impact

These operations change PostgreSQL client registrations, affect subsequent token requests and append operator-attributed administrative audit events.
