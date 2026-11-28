## Decisions

Preserve statement and condition order. Validate structural errors and unsupported effects or operators with the appropriate response. Keep PostgreSQL mutation and operator audit in one transaction. Route writes to the selected provider and verify readback through the existing detail endpoint.

### Concurrent PostgreSQL replacements

The current Rust implementation locks the policy row before reading its version and replacing its statements. Two Rust writers each receive a distinct committed version. The behavior required during coexistence with other writers remains an open compatibility decision.

For an ordinary PostgreSQL policy, pausing replacement requests and draining the outgoing transaction before switching writers avoids overlapping statement sets. A committed outgoing edit followed by a committed incoming edit advances the version twice. A rejected outgoing commit followed by a committed incoming edit advances it once. In both cases the incoming policy contains only its submitted statement sequence and retains any omitted metadata from the last committed version.

## Verification

Compare validation and authorization order, retries, duplicate names, concurrent edits, version changes, statement replacement, failed audits and provider failures. Verify the existing CLI and console create and save workflows.
