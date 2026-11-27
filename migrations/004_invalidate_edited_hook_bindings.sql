BEGIN;

CREATE FUNCTION pyloros_clear_edited_hook_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    EXECUTE format('DELETE FROM %I.pyloros_hook_bindings WHERE hook_id = $1', TG_TABLE_SCHEMA)
        USING NEW.id;
    RETURN NULL;
END;
$$;

CREATE TRIGGER pyloros_hook_source_changed
AFTER UPDATE ON hooks
FOR EACH ROW WHEN (OLD.code IS DISTINCT FROM NEW.code)
EXECUTE FUNCTION pyloros_clear_edited_hook_binding();

COMMIT;
