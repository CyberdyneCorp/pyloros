"""List committed Stripe events awaiting redelivery on the selected database."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import asyncio
import json
import os

import asyncpg


async def main():
    connection = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with connection.transaction(readonly=True):
            rows = await connection.fetch(
                "SELECT event_id, reason FROM stripe_events WHERE status = 'deferred' ORDER BY event_id"
            )
    finally:
        await connection.close()
    print(json.dumps([dict(row) for row in rows]))
    return 2 if rows else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
