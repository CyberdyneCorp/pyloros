SELECT jsonb_build_object(
    'id', u.id, 'email', u.primary_email, 'phone', u.primary_phone,
    'wallet_address', u.default_wallet_address, 'public_key', u.public_key,
    'is_active', u.is_active, 'is_email_verified', u.is_email_verified,
    'is_phone_verified', u.is_phone_verified, 'is_admin', u.is_admin,
    'organization_id', u.organization_id, 'avatar_url', u.extra_metadata->>'avatar_url',
    'organization', CASE WHEN o.id IS NOT NULL THEN jsonb_build_object(
        'id', o.id, 'short_name', o.short_name, 'name', o.name) END,
    'entitlements', (SELECT tokens FROM effective)
), u.created_at FROM users u
LEFT JOIN organizations o ON o.id=u.organization_id AND o.is_active
WHERE u.id=$1
