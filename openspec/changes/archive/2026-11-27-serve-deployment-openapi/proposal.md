## Why

Client tooling discovers the deployment API by fetching its root OpenAPI document.

## What Changes

Serve an operator-supplied OpenAPI JSON document at the root schema URL. Read and validate the configured file at startup.

## Impact

The deployment owns the document and can select the contract corresponding to its release.
