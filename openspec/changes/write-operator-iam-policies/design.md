## Decisions

Preserve statement and condition order. Validate structural errors and unsupported effects or operators with the appropriate response. Keep PostgreSQL mutation and operator audit in one transaction. Route writes to the selected provider and verify readback through the existing detail endpoint.

## Verification

Compare validation and authorization order, retries, duplicate names, concurrent edits, version changes, statement replacement, failed audits and provider failures. Verify the existing CLI and console create and save workflows.
