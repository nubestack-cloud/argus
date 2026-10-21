DROP INDEX IF EXISTS refresh_tokens_family_id_idx;
ALTER TABLE refresh_tokens DROP COLUMN family_id;
