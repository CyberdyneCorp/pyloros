SELECT jsonb_build_object(
    'local_id', r.id, 'ref', r.chain_role_id, 'name', r.name, 'description', r.description,
    'max_session_duration_s', r.max_session_duration_s,
    'policy_refs', ARRAY(
        SELECT jsonb_build_object('local_id', a.policy_id, 'ref', p.chain_policy_id)
        FROM iam_role_policies a LEFT JOIN iam_policies p ON p.id = a.policy_id
        WHERE a.role_id = r.id
    )
) FROM iam_roles r ORDER BY r.name
