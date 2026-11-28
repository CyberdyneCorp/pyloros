"""Count registered client identifiers that overlap at a role namespace separator."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import asyncio
import json
import os

import asyncpg


SUMMARY = """
WITH pairs AS (
    SELECT shorter.client_id AS shorter_id, longer.client_id AS longer_id,
           shorter.active AND longer.active AS both_active
    FROM oauth_clients AS longer
    CROSS JOIN LATERAL generate_series(2, char_length(longer.client_id)) AS pos(n)
    JOIN oauth_clients AS shorter ON shorter.client_id = left(longer.client_id, pos.n - 1)
    WHERE strpos(longer.client_id, ':') > 0 AND substr(longer.client_id, pos.n, 1) = ':'
)
SELECT count(*) AS overlapping_pairs,
       count(*) FILTER (WHERE both_active) AS active_pairs,
       count(DISTINCT shorter_id) AS shorter_identifiers,
       count(DISTINCT longer_id) AS longer_identifiers
FROM pairs
"""


async def main():
    connection = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with connection.transaction(readonly=True):
            counts = await connection.fetchrow(SUMMARY)
    finally:
        await connection.close()
    print(json.dumps(dict(counts)))


if __name__ == "__main__":
    asyncio.run(main())
