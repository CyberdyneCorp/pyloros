CREATE TABLE pyloros_hook_deliveries (
    id uuid PRIMARY KEY,
    hook_id uuid NOT NULL REFERENCES hooks(id) ON DELETE CASCADE,
    sha256 text NOT NULL REFERENCES pyloros_hook_artifacts(sha256),
    hook_name text NOT NULL,
    event_type text NOT NULL,
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    payload jsonb NOT NULL,
    timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 30),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX pyloros_hook_deliveries_ready ON pyloros_hook_deliveries(available_at, id);
