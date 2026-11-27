WITH registrations AS (
    SELECT (created_at AT TIME ZONE coalesce($2, current_setting('TimeZone')))::date AS date, count(*) AS count FROM users
    WHERE created_at >= statement_timestamp() - $1::int * interval '24 hours'
    GROUP BY 1
)
SELECT jsonb_build_object('registrations', coalesce(jsonb_agg(to_jsonb(registrations) ORDER BY date), '[]'),
                          'total', coalesce(sum(count), 0))
FROM registrations
