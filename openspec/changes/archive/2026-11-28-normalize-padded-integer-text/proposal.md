## Why

Some numeric strings with zero padding produce different page selections and field diagnostics during migration.

## What Changes

Normalize padding before integer bounds checks and preserve the submitted spelling in validation errors.

## Capabilities

### Modified Capabilities

- http-responses

## Impact

Query and JSON fields using the shared integer-text parser.
