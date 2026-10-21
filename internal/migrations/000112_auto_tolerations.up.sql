-- PROJECT.md T6: feed operator outcomes (dismissals, expiries) back into
-- promotion, by EXTENDING the existing toleration mechanism (migration 000041)
-- rather than building a second, parallel suppression path.
--
-- internal/orchestrator/db.go's SetState — the one function that ever writes
-- incidents.state — creates an incident_tolerations row automatically when an
-- incident closes Dismissed or Expired, scoped to that incident's own object
-- and the exact reasons its findings carried. The READ side needs no change
-- at all: internal/gateway/toleration.go's FindingTolerated already matches
-- on (cluster_id, object_key, reason) with no notion of who or what created
-- the rule, so an auto-created row is suppressed by the exact same query path
-- a human-created one already goes through, and it shows up on the same
-- TolerationsPage screen, removable the same way (DELETE /tolerations/{id}).
--
-- Mirrors migration 000047's precedent exactly for "no acting user": NULL
-- created_by plus an explicit boolean flag, never a sentinel string written
-- into a column every other reader (the LEFT JOIN to users) treats as a real
-- users.id. created_by stays NOT NULL in spirit for every rule a human
-- creates through POST /incidents/{id}/tolerate; the CHECK constraint below
-- makes that "NULL if and only if auto_created" precise rather than assumed.
ALTER TABLE incident_tolerations
  ALTER COLUMN created_by DROP NOT NULL,
  ADD COLUMN auto_created boolean NOT NULL DEFAULT false;

ALTER TABLE incident_tolerations
  ADD CONSTRAINT incident_tolerations_created_by_xor_auto
  CHECK ((created_by IS NULL) = auto_created);

COMMENT ON COLUMN incident_tolerations.auto_created IS
  'true only for a rule SetState created automatically on a Dismissed/Expired transition (PROJECT.md T6) — never for one a human created via POST /incidents/{id}/tolerate. The UI badges these differently; DELETE /tolerations/{id} un-suppresses either kind identically.';
