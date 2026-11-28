"""List committed Stripe events awaiting redelivery on the selected database."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import asyncio
import json
import os
from shutil import copyfileobj
import sys
from tempfile import SpooledTemporaryFile

import asyncpg


async def write_report(connection, output):
    query = "SELECT event_id, reason FROM stripe_events WHERE status = 'deferred' ORDER BY event_id"
    pending = False
    output.write("[")
    async with connection.transaction(readonly=True):
        async for row in connection.cursor(query, prefetch=256):
            if pending:
                output.write(", ")
            output.write(json.dumps(dict(row)))
            pending = True
    output.write("]\n")
    return pending


async def main():
    with SpooledTemporaryFile(mode="w+", encoding="utf-8", max_size=1 << 20) as report:
        connection = await asyncpg.connect(os.environ["DATABASE_URL"])
        try:
            pending = await write_report(connection, report)
        finally:
            await connection.close()
        report.seek(0)
        copyfileobj(report, sys.stdout)
    return 2 if pending else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
