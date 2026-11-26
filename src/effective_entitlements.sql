SELECT ARRAY(
    SELECT DISTINCT concat_ws(':', e.product_key, NULLIF(e.plan, '')) COLLATE "C"
    FROM entitlements e
    WHERE (e.user_id = $1 OR e.organization_id = (
        SELECT o.id FROM users u
        JOIN organizations o ON o.id = u.organization_id AND o.is_active
        WHERE u.id = $1
    ))
    AND e.status = 'active'
    AND (e.expires_at IS NULL OR e.expires_at > now())
    ORDER BY 1
) AS tokens
