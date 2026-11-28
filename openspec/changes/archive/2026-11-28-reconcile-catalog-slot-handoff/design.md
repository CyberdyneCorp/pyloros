## Decisions

Pause admission for both callers, drain the outgoing write, then read inventory and the recorded audit from the primary. Hold admission through the pool switch. The incoming writer uses the committed catalog state.

## Verification

Use two instances of each API on a shared database. Exercise each catalog in both switch directions, including a transaction rejected at commit.
