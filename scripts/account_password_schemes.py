"""Count stored account password prefixes for migration planning."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import asyncio
import os

import asyncpg


COUNTS = """
WITH totals AS (
    SELECT CASE
        WHEN password_hash IS NULL THEN 'absent'
        WHEN password_hash ~ '^[$](argon2i|argon2d|argon2id)[$]' THEN 'argon2'
        WHEN password_hash ~ '^[$]2[aby]?[$]' THEN 'bcrypt'
        ELSE 'unrecognized'
    END AS family, count(*) AS accounts
    FROM users
    GROUP BY family
)
SELECT json_build_object(
    'argon2', coalesce(max(accounts) FILTER (WHERE family = 'argon2'), 0),
    'bcrypt', coalesce(max(accounts) FILTER (WHERE family = 'bcrypt'), 0),
    'absent', coalesce(max(accounts) FILTER (WHERE family = 'absent'), 0),
    'unrecognized', coalesce(max(accounts) FILTER (WHERE family = 'unrecognized'), 0)
)
FROM totals
"""


async def main():
    connection = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with connection.transaction(readonly=True):
            report = await connection.fetchval(COUNTS)
    finally:
        await connection.close()
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
