## Why

A device without an interactive browser needs a signed-in user to authorize its session from another browser during the backend migration.

## What Changes

Support device authorization requests, the browser verification and decision endpoints, and the device grant at the shared token endpoint.

## Impact

The Rust service shares pending approvals and issued sessions through PostgreSQL. The existing browser experience and device clients must work when requests reach different backend versions.
