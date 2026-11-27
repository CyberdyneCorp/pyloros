BEGIN;

CREATE TABLE pyloros_relationship_models (
    client_id uuid PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE,
    model jsonb NOT NULL CHECK (jsonb_typeof(model) = 'object')
);

CREATE TABLE pyloros_user_relationships (
    client_id uuid NOT NULL REFERENCES pyloros_relationship_models(client_id) ON DELETE CASCADE,
    object_type text COLLATE "C" NOT NULL CHECK (octet_length(object_type) BETWEEN 1 AND 128),
    object_id text COLLATE "C" NOT NULL CHECK (octet_length(object_id) BETWEEN 1 AND 512),
    relation text COLLATE "C" NOT NULL CHECK (octet_length(relation) BETWEEN 1 AND 128),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, object_type, object_id, relation, user_id)
);

CREATE INDEX pyloros_user_relationships_by_account ON pyloros_user_relationships (user_id);

CREATE TABLE pyloros_object_relationships (
    client_id uuid NOT NULL REFERENCES pyloros_relationship_models(client_id) ON DELETE CASCADE,
    object_type text COLLATE "C" NOT NULL CHECK (octet_length(object_type) BETWEEN 1 AND 128),
    object_id text COLLATE "C" NOT NULL CHECK (octet_length(object_id) BETWEEN 1 AND 512),
    relation text COLLATE "C" NOT NULL CHECK (octet_length(relation) BETWEEN 1 AND 128),
    subject_type text COLLATE "C" NOT NULL CHECK (octet_length(subject_type) BETWEEN 1 AND 128),
    subject_id text COLLATE "C" NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 512),
    PRIMARY KEY (client_id, object_type, object_id, relation, subject_type, subject_id)
);

COMMIT;
