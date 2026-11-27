WITH ages AS (
    SELECT trunc(extract(epoch FROM $1::timestamptz - created_at))::bigint AS age
    FROM sessions WHERE revoked_at IS NULL AND expires_at > $1
), metrics AS (
    SELECT count(*) AS live_sessions,
           coalesce(trunc(avg(age)), 0)::bigint AS mean_session_age_s,
           coalesce(floor(percentile_cont(0.5) WITHIN GROUP (ORDER BY age)), 0)::bigint AS median_session_age_s
    FROM ages
)
SELECT $2::jsonb || to_jsonb(metrics) FROM metrics
