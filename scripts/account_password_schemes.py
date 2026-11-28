"""Count stored account password prefixes for migration planning."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import argparse
import asyncio
import os

import asyncpg


BCRYPT_PREFIX = "^[$]2[aby]?[$]"

COUNTS = f"""
WITH totals AS (
    SELECT CASE
        WHEN password_hash IS NULL THEN 'absent'
        WHEN password_hash ~ '^[$](argon2i|argon2d|argon2id)[$]' THEN 'argon2'
        WHEN password_hash ~ '{BCRYPT_PREFIX}' THEN 'bcrypt'
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


RECOVERY_COUNTS = f"""
WITH accounts AS (
    SELECT is_active, coalesce(primary_email ~ '[^[:space:]]', false) AS has_email
    FROM users
    WHERE password_hash ~ '{BCRYPT_PREFIX}'
)
SELECT json_build_object(
    'active_with_email', count(*) FILTER (WHERE is_active AND has_email),
    'active_without_email', count(*) FILTER (WHERE is_active AND NOT has_email),
    'inactive_with_email', count(*) FILTER (WHERE NOT is_active AND has_email),
    'inactive_without_email', count(*) FILTER (WHERE NOT is_active AND NOT has_email)
)
FROM accounts
"""


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bcrypt-recovery", action="store_true",
        help="count bcrypt accounts by active status and stored primary email",
    )
    args = parser.parse_args()
    connection = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with connection.transaction(readonly=True):
            report = await connection.fetchval(RECOVERY_COUNTS if args.bcrypt_recovery else COUNTS)
    finally:
        await connection.close()
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
