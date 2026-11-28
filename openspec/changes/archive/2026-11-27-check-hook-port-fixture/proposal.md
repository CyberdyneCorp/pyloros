## Why
Operators need repeatable behavioral evidence for each hook port before selecting it in a deployment.
## What Changes
Add a local fixture check to the executable and justfile. Report the component digest after an exact match.
## Impact
The check uses the isolated worker and local files.
