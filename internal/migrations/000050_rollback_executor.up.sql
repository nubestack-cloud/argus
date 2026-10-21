-- Give the "undo" a durable, queryable home, and a way to say it has been used.
--
-- WHAT ALREADY EXISTED, AND WHY IT WAS NOT ENOUGH
--
-- Every PatchResourceLimits and RevertContainerImage plan has carried a signed
-- compensating action since WORKLOG §93 — captured from the live object BEFORE
-- the mutation, because that is the only moment the pre-change values are
-- knowable. Nothing could ever replay it. `CapRemediationRollback` has been in
-- the capability catalogue since the first authz pass, granted to three roles,
-- and enforced by no handler.
--
-- Its only persistent home was `audit_events.details["rollback"]`, and that is
-- the wrong place to READ an undo from, for two reasons that are easy to miss:
--
--   1. `audit_events.details` is deliberately EXCLUDED from the audit hash chain
--      (lld/05 §7). So the rollback was durable and attributable but not
--      tamper-evident — the one property that matters most for a value you are
--      about to write back into a production cluster.
--   2. It is a JSON blob in an append-only log keyed by actor and time. Answering
--      "can this execution be undone, and has it been?" meant scanning audit
--      history for a details member, which no index helps with.
--
-- The execution is the thing being undone, so the undo belongs on the execution.
ALTER TABLE remediation_executions
  -- The compensating action, in the same shape remediation.CompensatingAction
  -- signs and the same lowercase-keyed params convention PlanContent uses. All
  -- three are NULL together for an action type that has no undo, which is a real
  -- state and not a gap: a RestartPod has nothing to put back.
  ADD COLUMN rollback_action_type text,
  ADD COLUMN rollback_params jsonb,
  ADD COLUMN rollback_description text,

  -- The execution that undid this one. Self-referential rather than a boolean:
  -- "has this been rolled back" and "by what, and when" are the same question,
  -- and a boolean answers only the first. Also makes the reverse direction free
  -- — an undo row's own target is one join away.
  --
  -- No FK, deliberately: remediation_executions is not partitioned, so an FK
  -- would work, but it would also make deleting an execution during retention
  -- fail rather than simply orphan a reference nobody reads any more.
  ADD COLUMN rolled_back_by_execution_id text,

  -- What the forward change SET, so the undo can refuse when the world has moved.
  -- This is the analogue of the pull-request path's expectedCurrentValue: a
  -- compensating action derived from state captured before the forward change is
  -- only safe to apply while the forward change is still what is running. If
  -- someone else has since changed the same field, replaying the undo would
  -- discard their change, not ours.
  --
  -- Stored as text because it is compared, not interpreted — every action type
  -- this applies to changes one scalar (a replica count, a quantity, an image).
  ADD COLUMN forward_applied_value text,

  ADD CONSTRAINT remediation_executions_rollback_complete
    CHECK ((rollback_action_type IS NULL) = (rollback_params IS NULL));

-- "Which executions can still be undone" is the query the UI and the operator
-- both ask, and it is narrow: succeeded, has an undo, has not been undone yet.
CREATE INDEX remediation_executions_undoable_idx
  ON remediation_executions (incident_id, executed_at DESC)
  WHERE outcome = 'succeeded' AND rollback_action_type IS NOT NULL AND rolled_back_by_execution_id IS NULL;
