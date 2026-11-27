## Why

Account owners and support administrators need a downloadable account history that excludes credentials and protects other people named in the same records.

## What Changes

Provide first-party and administrative JSON downloads with the existing personal-data inventory, section limits and export auditing.

## Capabilities

### New Capabilities
- `subject-data-export` defines personal-data downloads and subject matching.

## Impact

The Rust service reads PostgreSQL account and identity records, records successful exports and applies an account-specific quota to self-service requests.
