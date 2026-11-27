SELECT jsonb_build_object(
    'local_id', g.id, 'ref', g.chain_group_id, 'name', g.name, 'description', g.description,
    'member_refs', ARRAY(
        SELECT jsonb_build_object('local_id', m.identity_id, 'ref', i.chain_token_id)
        FROM iam_group_members m LEFT JOIN iam_identities i ON i.id = m.identity_id
        WHERE m.group_id = g.id
    ),
    'policy_refs', ARRAY(
        SELECT jsonb_build_object('local_id', a.policy_id, 'ref', p.chain_policy_id)
        FROM iam_group_policies a LEFT JOIN iam_policies p ON p.id = a.policy_id
        WHERE a.group_id = g.id
    )
) FROM iam_groups g ORDER BY g.name
