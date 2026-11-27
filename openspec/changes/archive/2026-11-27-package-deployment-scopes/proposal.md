## Why
A migrating issuer needs its built-in scopes on first boot, before any registry rows exist. Operators can package the deployment catalog alongside the release in their own build pipeline.

## What Changes
Accept a build-time list of scope names. Use it as the default discovery base and make the same names available to administrative scope and protected-resource configuration.

## Capabilities
### Modified Capabilities
- issuer-discovery

## Impact
Release packaging, discovery and scope registry configuration.
