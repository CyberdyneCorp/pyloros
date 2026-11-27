CREATE TABLE pyloros_hook_bindings (
    hook_id uuid PRIMARY KEY REFERENCES hooks(id) ON DELETE CASCADE,
    sha256 text NOT NULL REFERENCES pyloros_hook_artifacts(sha256)
);
