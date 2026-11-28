"""List PostgreSQL table constraints and triggers that can run at commit."""

# /// script
# requires-python = ">=3.11"
# dependencies = ["asyncpg==0.31.0"]
# ///

import asyncio
import json
import os

import asyncpg


CATALOG = """
WITH checks AS (
    SELECT conrelid AS relation_id, conname AS name, 'constraint' AS kind,
           condeferred AS initially_deferred, NULL::text AS trigger_mode
      FROM pg_catalog.pg_constraint WHERE condeferrable
    UNION ALL
    SELECT tgrelid, tgname, 'trigger', tginitdeferred, tgenabled::text
      FROM pg_catalog.pg_trigger WHERE tgdeferrable
)
SELECT ns.nspname AS schema, rel.relname AS relation, checks.kind, checks.name,
       checks.initially_deferred, checks.trigger_mode
  FROM checks
  JOIN pg_catalog.pg_class rel ON rel.oid = checks.relation_id
  JOIN pg_catalog.pg_namespace ns ON ns.oid = rel.relnamespace
 WHERE ns.nspname !~ '^pg_' AND ns.nspname <> 'information_schema'
 ORDER BY ns.nspname, rel.relname, checks.kind, checks.name
"""


async def main():
    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        async with conn.transaction(readonly=True):
            rows = await conn.fetch(CATALOG)
    finally:
        await conn.close()
    print(json.dumps([dict(row) for row in rows], indent=2))


if __name__ == "__main__":
    asyncio.run(main())
