"""Count repeated statement positions in chain-linked PostgreSQL IAM policies."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import asyncio
import json
import os

import asyncpg


COUNTS = """
WITH collisions AS (
    SELECT s.policy_id, s.sort_order, count(*) AS rows_at_position
    FROM iam_policy_statements AS s
    JOIN iam_policies AS p ON p.id = s.policy_id
    WHERE p.chain_policy_id IS NOT NULL
    GROUP BY s.policy_id, s.sort_order
    HAVING count(*) > 1
)
SELECT count(DISTINCT policy_id) AS affected_policies,
       count(*) AS repeated_positions,
       coalesce(sum(rows_at_position - 1), 0)::bigint AS excess_rows
FROM collisions
"""


async def main():
    connection = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with connection.transaction(readonly=True):
            counts = await connection.fetchrow(COUNTS)
    finally:
        await connection.close()
    print(json.dumps(dict(counts)))


if __name__ == "__main__":
    asyncio.run(main())
