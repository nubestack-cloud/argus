-- Reversible with no data loss: repo_key is derived, so dropping it throws away
-- nothing that cannot be recomputed. The lookup reverts to exact URL matching,
-- which means the bug above returns — worth saying, so a rollback is a decision
-- rather than a surprise.
DROP INDEX IF EXISTS repository_bindings_repo_key_idx;
ALTER TABLE repository_bindings DROP COLUMN IF EXISTS repo_key;
