## Why
A migration deployment can serve a different browser page when its launcher supplies the API description but omits the signed-out or authorization pages.

## What Changes
Provide a relocatable launcher for the migration distribution. Select the packaged assets by default and honor explicit deployment overrides.

## Capabilities
### Modified Capabilities
- `http-responses` describes how a packaged migration server selects deployment assets.

## Impact
A deployment assembler supplies the existing assets next to its release binaries.
