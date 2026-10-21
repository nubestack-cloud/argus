-- Reversible only as far as the data allows, same honesty as migration
-- 000047's own down.sql: restoring created_by's NOT NULL fails outright if
-- any auto-created rule has been recorded, because those rows have no author
-- to put back. If this rollback fails for that reason, the installation has
-- genuinely used auto-suppression and the honest fix is to decide what
-- happens to those rows first, not to make this statement lenient.
ALTER TABLE incident_tolerations DROP CONSTRAINT IF EXISTS incident_tolerations_created_by_xor_auto;
ALTER TABLE incident_tolerations DROP COLUMN IF EXISTS auto_created;
ALTER TABLE incident_tolerations ALTER COLUMN created_by SET NOT NULL;
