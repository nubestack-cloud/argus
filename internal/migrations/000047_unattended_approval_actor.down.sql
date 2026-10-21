-- Reversible only as far as the data allows, and that limit is worth naming
-- rather than hiding behind an IF EXISTS.
--
-- Restoring NOT NULL fails outright if any unattended decision has been
-- recorded, because those rows have no actor to put back — there is no correct
-- value to invent, and inventing one would attribute a machine decision to
-- whichever user id was chosen. If this rollback fails for that reason, the
-- installation has genuinely used unattended execution and the honest fix is to
-- decide what should happen to those rows first, not to make this statement
-- lenient.
ALTER TABLE remediation_approval_decisions
  DROP CONSTRAINT IF EXISTS remediation_approval_decisions_actor_xor_unattended;
ALTER TABLE remediation_approval_decisions DROP COLUMN IF EXISTS unattended;
ALTER TABLE remediation_approval_decisions ALTER COLUMN actor_id SET NOT NULL;
