"""Count repeated statement positions in PostgreSQL IAM policies (chain-linked by default)."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import argparse
import asyncio
import json
import os

import asyncpg


POSITION_COUNTS = """
WITH collisions AS (
    SELECT s.policy_id, s.sort_order, count(*) AS rows_at_position
    FROM iam_policy_statements AS s
    JOIN iam_policies AS p ON p.id = s.policy_id
    WHERE $1::boolean OR p.chain_policy_id IS NOT NULL
    GROUP BY s.policy_id, s.sort_order
    HAVING count(*) > 1
)
SELECT count(DISTINCT policy_id) AS affected_policies,
       count(*) AS repeated_positions,
       coalesce(sum(rows_at_position - 1), 0)::bigint AS excess_rows
FROM collisions
"""


CONTENT_COUNTS = """
WITH repeated AS (
    SELECT s.policy_id, count(*) AS copies
    FROM iam_policy_statements AS s
    JOIN iam_policies AS p ON p.id = s.policy_id
    WHERE $1::boolean OR p.chain_policy_id IS NOT NULL
    GROUP BY s.policy_id, s.sid, s.effect, s.actions, s.resources, s.conditions
    HAVING count(*) > 1
)
SELECT count(DISTINCT policy_id) AS affected_policies,
       count(*) AS repeated_rules,
       coalesce(sum(copies - 1), 0)::bigint AS excess_rows
FROM repeated
"""


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule-content", action="store_true", help="compare stored rule content across positions")
    parser.add_argument("--all-policies", action="store_true", help="include policies without a chain identifier")
    args = parser.parse_args()
    connection = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with connection.transaction(readonly=True):
            query = CONTENT_COUNTS if args.rule_content else POSITION_COUNTS
            counts = await connection.fetchrow(query, args.all_policies)
    finally:
        await connection.close()
    print(json.dumps(dict(counts)))


if __name__ == "__main__":
    asyncio.run(main())
