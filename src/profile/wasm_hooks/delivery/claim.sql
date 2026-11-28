SELECT q.id, q.hook_id, q.hook_name, q.event_type,
       CASE WHEN q.event_type = 'user_deleted' THEN (q.payload->>'user_id')::uuid
            ELSE q.user_id END AS user_id,
       CASE
           WHEN q.event_type = 'user_deleted' THEN
               json_build_object('event_type', q.event_type, 'user_id', q.payload->'user_id')::text
           WHEN q.event_type IN ('user_registered', 'user_logged_in', 'entitlement_granted',
                               'entitlement_revoked', 'role_granted', 'role_revoked') THEN (
               -- JSONB does not retain source member order. Order only the fields
               -- that survived enqueue-time and delivery-time privacy filtering.
               SELECT '{' || string_agg(to_json(key)::text || ': ' || value::text, ', '
                   ORDER BY array_position(
                       CASE WHEN q.event_type IN ('entitlement_granted', 'entitlement_revoked')
                            THEN ARRAY['product_key','plan','entitlement_id','source','organization_id','event_type','user_id']
                            WHEN q.event_type IN ('role_granted', 'role_revoked')
                            THEN ARRAY['client_id','role_key','organization_id','event_type','user_id']
                            ELSE ARRAY['email','address','user_agent','ip','event_type','user_id']
                       END, key), key COLLATE "C") || '}'
               FROM jsonb_each(q.payload)
               WHERE q.event_type NOT IN ('user_registered', 'user_logged_in')
                  OR h.receive_pii OR key IN ('event_type', 'user_id')
           )
           ELSE q.payload::text
       END AS payload,
       q.timeout_seconds, a.component
FROM pyloros_hook_deliveries q
JOIN hooks h ON h.id = q.hook_id
JOIN pyloros_hook_artifacts a ON a.sha256 = q.sha256
WHERE q.available_at <= clock_timestamp()
ORDER BY q.available_at, q.id
LIMIT 1 FOR UPDATE OF q SKIP LOCKED
