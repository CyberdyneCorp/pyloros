SELECT jsonb_build_object(
    'local_id', i.id, 'ref', i.chain_token_id, 'user_id', i.user_id, 'email', i.email,
    'owner_address', i.owner_address, 'public_key', i.public_key, 'metadata_uri', i.metadata_uri,
    'policy_refs', ARRAY(
        SELECT jsonb_build_object('local_id', a.policy_id, 'ref', p.chain_policy_id)
        FROM iam_identity_policies a LEFT JOIN iam_policies p ON p.id = a.policy_id
        WHERE a.identity_id = i.id
    )
), i.status, i.transfer_mode, (
    SELECT jsonb_build_object(
        'identity_ref', jsonb_build_object('local_id', i.id, 'ref', i.chain_token_id),
        'policy_ref', jsonb_build_object('local_id', b.policy_id, 'ref', p.chain_policy_id)
    ) FROM iam_permission_boundaries b LEFT JOIN iam_policies p ON p.id = b.policy_id
    WHERE b.identity_id = i.id
) FROM iam_identities i
