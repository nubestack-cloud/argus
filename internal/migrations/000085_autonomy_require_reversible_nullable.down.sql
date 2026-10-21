-- Reverse of 000085: restore the NOT NULL constraint. Any row that picked
-- up a NULL while this migration was applied is backfilled to true (the
-- safe direction, and DefaultAutonomyPolicy's own value) rather than false,
-- so rolling back never silently re-creates the permissive state BUGS.md 97
-- describes.
UPDATE org_settings SET autonomy_require_reversible_for_auto_approve = true
  WHERE autonomy_require_reversible_for_auto_approve IS NULL;

ALTER TABLE org_settings
  ALTER COLUMN autonomy_require_reversible_for_auto_approve SET NOT NULL;
