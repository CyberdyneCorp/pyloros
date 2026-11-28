## Context

Both writers share a PostgreSQL primary. The routing layer controls which pool accepts refresh and revocation requests during a switch.

## Decisions

Hold admission in both directions until previously admitted writes finish and their committed effects are visible. Exercise both possible outgoing operations. Check the session, outstanding refresh records and committed operator audit after the new writer handles the next operation.

## Scope

This rehearsal covers an administrator revoking an ordinary login session. Routing and draining additional producers depends on the deployment.
