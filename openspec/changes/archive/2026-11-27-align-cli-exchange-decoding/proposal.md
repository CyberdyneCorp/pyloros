## Why

CLI callers can encode JSON in several Unicode formats. Exchange should recognize the same request fields in each format.

## What Changes

Align CLI exchange document decoding and error responses with the public request contract.

## Capabilities

### Modified Capabilities
- external-oauth

## Impact

The CLI exchange HTTP handler and its tests.
