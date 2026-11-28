"""Count registered client identifiers that overlap at a role namespace separator."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import argparse
import asyncio
import json
import os

import asyncpg


REGISTERED_PAIRS = """
WITH pairs AS (
    SELECT shorter.client_id AS shorter_id, longer.client_id AS longer_id,
           shorter.active AND longer.active AS both_active
    FROM oauth_clients AS longer
    CROSS JOIN LATERAL generate_series(2, char_length(longer.client_id)) AS pos(n)
    JOIN oauth_clients AS shorter ON shorter.client_id = left(longer.client_id, pos.n - 1)
    WHERE strpos(longer.client_id, ':') > 0 AND substr(longer.client_id, pos.n, 1) = ':'
)
"""

REGISTRY = """
SELECT count(*) AS overlapping_pairs,
       count(*) FILTER (WHERE both_active) AS active_pairs,
       count(DISTINCT shorter_id) AS shorter_identifiers,
       count(DISTINCT longer_id) AS longer_identifiers
FROM pairs
"""


ASSIGNMENTS = """
, candidate_groups AS (
    SELECT DISTINCT g.id
    FROM iam_groups AS g
    CROSS JOIN LATERAL generate_series(5, char_length(g.name)) AS pos(n)
    JOIN (SELECT DISTINCT longer_id FROM pairs) AS owners
      ON owners.longer_id = substr(g.name, 4, pos.n - 4)
    WHERE starts_with(g.name, 'rp:') AND substr(g.name, pos.n, 1) = ':'
)
SELECT count(DISTINCT g.id) AS candidate_groups,
       count(DISTINCT m.group_id) AS populated_groups,
       count(m.identity_id) AS membership_rows,
       count(DISTINCT m.identity_id) AS distinct_identities
FROM candidate_groups AS g
LEFT JOIN iam_group_members AS m ON m.group_id = g.id
"""


async def main(assignments):
    connection = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with connection.transaction(readonly=True):
            counts = await connection.fetchrow(REGISTERED_PAIRS + (ASSIGNMENTS if assignments else REGISTRY))
    finally:
        await connection.close()
    print(json.dumps(dict(counts)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assignments", action="store_true", help="count matching PostgreSQL IAM groups and memberships")
    asyncio.run(main(parser.parse_args().assignments))
