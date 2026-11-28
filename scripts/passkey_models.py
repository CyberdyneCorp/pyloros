"""Count unrevoked credentials by authenticator model and credential algorithm."""

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
            rows = await connection.fetch("""
                SELECT aaguid, algorithm AS credential_algorithm, count(*) AS credentials
                FROM passkeys
                WHERE revoked_at IS NULL
                GROUP BY aaguid, algorithm
                ORDER BY aaguid NULLS LAST, algorithm
            """)
    finally:
        await connection.close()
    print(json.dumps([dict(row) for row in rows]))


if __name__ == "__main__":
    asyncio.run(main())
