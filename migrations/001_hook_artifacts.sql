-- Apply once to the shared PostgreSQL database before enabling artifact storage.
CREATE TABLE pyloros_hook_artifacts (
    sha256 text PRIMARY KEY,
    component bytea NOT NULL,
    abi text NOT NULL,
    installed_by uuid NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(component) BETWEEN 1 AND 4194304),
    CHECK (sha256 = encode(sha256(component), 'hex'))
);
