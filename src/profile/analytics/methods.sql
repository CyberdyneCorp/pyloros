WITH identities AS (
    SELECT type, provider, count(*) AS count FROM user_identities GROUP BY type, provider
), methods AS (
    SELECT 0 AS position, 'password' AS type, 'local' AS provider,
           greatest(0, $1::bigint -
                       coalesce(sum(count) FILTER (WHERE type IN ('oauth', 'wallet')), 0)) AS count
    FROM identities
    UNION ALL
    SELECT 1, type, provider, count FROM identities
)
SELECT jsonb_build_object('methods', jsonb_agg(to_jsonb(methods) - 'position' ORDER BY position, type, provider),
                          'total', sum(count))
FROM methods
