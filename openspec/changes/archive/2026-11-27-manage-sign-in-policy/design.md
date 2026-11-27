## Approach

Read the singleton policy from PostgreSQL and support databases without a seeded row. Validate cadence and email delivery settings before changing state. Store the new cadence, timestamp and operator audit entry atomically. Return the representation consumed by the existing console and CLI.
