DROP INDEX IF EXISTS helm_link_declines_manifest_lookup_idx;
ALTER TABLE helm_link_declines DROP CONSTRAINT IF EXISTS helm_link_declines_exactly_one_form;
-- Manifest-mode rows have no release_name/namespace, so they cannot survive
-- the NOT NULL this restores — delete them first rather than leave the
-- rollback itself failing on real data.
DELETE FROM helm_link_declines WHERE object_gvk IS NOT NULL;
ALTER TABLE helm_link_declines DROP COLUMN IF EXISTS object_gvk;
ALTER TABLE helm_link_declines DROP COLUMN IF EXISTS object_namespace;
ALTER TABLE helm_link_declines DROP COLUMN IF EXISTS object_name;
ALTER TABLE helm_link_declines ALTER COLUMN release_name SET NOT NULL;
ALTER TABLE helm_link_declines ALTER COLUMN namespace SET NOT NULL;
