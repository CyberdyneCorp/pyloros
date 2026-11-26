SELECT u.primary_email, u.is_admin, u.is_email_verified, c.access_token_audience AS default_audience,
       CASE WHEN primary_org.id IS NOT NULL THEN jsonb_build_object(
           'id', primary_org.id, 'short_name', COALESCE(NULLIF(primary_org.short_name, ''), primary_org.name)
       ) END AS primary_org,
       COALESCE((
           SELECT jsonb_agg(jsonb_build_object(
               'id', o.id, 'short_name', COALESCE(NULLIF(o.short_name, ''), o.name), 'github_login', o.github_login
           ) ORDER BY lower(o.short_name), o.id)
           FROM user_organizations m JOIN organizations o ON m.organization_id = o.id
           WHERE m.user_id = u.id AND o.is_active
       ), '[]'::jsonb) AS memberships,
       ARRAY(
           SELECT DISTINCT concat_ws(':', e.product_key, NULLIF(e.plan, '')) COLLATE "C"
           FROM entitlements e
           WHERE (e.user_id = u.id OR e.organization_id = primary_org.id)
             AND e.status = 'active' AND (e.expires_at IS NULL OR e.expires_at > $3)
           ORDER BY 1
       ) AS entitlements
FROM users u LEFT JOIN oauth_clients c ON c.client_id = $2 AND c.active
LEFT JOIN organizations primary_org ON primary_org.id = u.organization_id AND primary_org.is_active
WHERE u.id = $1 AND u.is_active AND ($2::text IS NULL OR c.client_id IS NOT NULL)
