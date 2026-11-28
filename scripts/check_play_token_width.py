"""Report the declared widths of both Google Play token storage columns."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import asyncio
import json
import os

import asyncpg


COLUMNS = """
WITH targets(relation, attribute) AS (
    VALUES ('google_purchases', 'purchase_token'), ('entitlements', 'external_ref')
)
SELECT t.relation, t.attribute, n.nspname AS schema, c.data_type,
       c.character_maximum_length AS max_characters,
       coalesce(c.domain_name IS NULL AND c.data_type IN ('text', 'character varying')
           AND (c.character_maximum_length IS NULL OR c.character_maximum_length >= 512),
           false) AS width_verified
FROM targets t
LEFT JOIN pg_catalog.pg_class r ON r.oid = pg_catalog.to_regclass(t.relation)
LEFT JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
LEFT JOIN information_schema.columns c ON (c.table_schema, c.table_name, c.column_name)
                                       = (n.nspname, r.relname, t.attribute)
ORDER BY t.relation
"""


async def main():
    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with conn.transaction(readonly=True):
            rows = await conn.fetch(COLUMNS)
    finally:
        await conn.close()
    print(json.dumps([dict(row) for row in rows], indent=2))
    return 0 if all(row["width_verified"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
