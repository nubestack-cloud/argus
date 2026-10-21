-- Who decided, when nobody decided.
--
-- Migration 000046 added the unattended-execution switch and its blast-radius
-- cap. This one fixes the record-keeping problem that switch creates, which is
-- narrow but not cosmetic: remediation_approval_decisions.actor_id is
-- `text NOT NULL`, and an unattended execution has no actor. Every execution
-- has a decision behind it, and dropping the row for unattended ones would mean
-- any query joining executions to decisions silently omits exactly the
-- executions nobody watched — the ones most worth being able to audit.
--
-- The alternative considered and rejected was a sentinel actor id
-- ('system:unattended' or similar). That writes a user id that is not a user
-- into a column every reader treats as one, so every consumer would need to
-- know the magic string to avoid attributing a machine decision to a person.
-- NULL plus an explicit flag cannot be misread that way.
ALTER TABLE remediation_approval_decisions
  ALTER COLUMN actor_id DROP NOT NULL;

-- A column rather than an inference from actor_id IS NULL, for the same reason
-- migration 000046 gave remediation_executions.unattended its own column:
-- "nobody approved this" and "no human approved this" must not be the same
-- fact. A future service-principal or API-token path would also have a NULL
-- user id while being very much attended.
ALTER TABLE remediation_approval_decisions
  ADD COLUMN unattended boolean NOT NULL DEFAULT false;

-- The invariant, enforced here rather than trusted to the API layer: exactly
-- one of "a person decided" and "policy decided" is true of every row. Without
-- this, the nullable column above quietly permits two nonsense states — an
-- unattended decision that names an approver, and an attended one that names
-- nobody — and the second is the one a forgotten code path would actually
-- produce.
ALTER TABLE remediation_approval_decisions
  ADD CONSTRAINT remediation_approval_decisions_actor_xor_unattended
  CHECK ((actor_id IS NULL) = unattended);
