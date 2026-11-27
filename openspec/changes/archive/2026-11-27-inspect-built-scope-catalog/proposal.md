## Why
Two service executables built from the same revision can have different built-in scope catalogs. Release verification needs to inspect the artifact selected for deployment.

## What Changes
Expose the embedded catalog through a read-only command on the executable.

## Capabilities
### Modified Capabilities
- issuer-discovery

## Impact
Release packaging and verification tooling.
