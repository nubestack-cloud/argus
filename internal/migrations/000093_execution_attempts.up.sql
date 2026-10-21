-- The durable "we are about to change a cluster" record, written BEFORE the
-- mutation and settled after it.
--
-- WHAT WAS WRONG WITHOUT IT
--
-- Two live-path faults, found in review, share one root: the only durable
-- marker that an execution was in flight was incidents.state = 'Executing',
-- and nothing in the product ever reconciled it.
--
--   1. handleApproveIncident commits AwaitingApproval -> Executing in its own
--      transaction, performs the tunnel call, and records the outcome in a
--      second transaction. If the client disconnects (net/http cancels
--      r.Context(), and an already-cancelled context makes every pgx operation
--      fail immediately) or the hub dies between those two commits, nothing
--      ever writes the outcome. The stale-object sweeper deliberately excludes
--      Executing because "another writer owns the state" — true while the hub
--      is alive, false the moment it is not — so the incident stays Executing
--      forever, while the cluster mutation may or may not have landed.
--
--   2. The rollback endpoint never entered Executing at all. Its pre-mutation
--      record was an audit event, which is durable but is not a row anything
--      queries to ask "is there an unfinished change out there?".
--
-- An audit event cannot serve this purpose: audit_events is append-only,
-- keyed by actor and time, and its `details` blob is deliberately excluded
-- from the hash chain (lld/05-data-model.md §7). What was missing is a row
-- with a lifecycle — open, then settled — that a reconciler can select on.
--
-- WHY IT IS SEPARATE FROM remediation_executions
--
-- remediation_executions is the record of what the cluster DID: it has an
-- outcome, and every reader treats a row's existence as "this attempt
-- resolved". Writing a provisional row there and updating it later would make
-- every one of those readers — the blast-radius budget, the circuit breaker,
-- the undoable-executions index, insights — count attempts that have not
-- finished, which is exactly the class of untruth this change exists to
-- remove. So the attempt is its own table, and settling one writes the
-- execution row in the same transaction.
--
-- expires_at IS THE OWNERSHIP RULE
--
-- The reconciler must never settle an attempt some live request is still
-- working on. Rather than a heartbeat, a lease table, or a process id (none
-- of which survive a second hub replica honestly), the attempt carries the
-- deadline of the bounded context the dispatching request runs under, plus a
-- grace margin. Past that instant no live owner can still be in its tunnel
-- call, so concluding "we cannot tell whether this landed" is sound —
-- and it is sound whether the owner was one hub or one of several.
CREATE TABLE remediation_execution_attempts (
  id                text NOT NULL PRIMARY KEY,   -- 'exat_...' (domain.PrefixExecutionAttempt)
  tenant_id         text NOT NULL,
  cluster_id        text NOT NULL,
  incident_id       text NOT NULL,
  recommendation_id text NOT NULL REFERENCES remediation_recommendations(id),

  -- 'forward' is an approved plan being applied; 'undo' is a compensating
  -- action being replayed by the rollback endpoint. They settle differently
  -- (see success_state), so the difference has to be a stored fact rather
  -- than something inferred from undo_of_execution_id being non-NULL.
  kind        text NOT NULL CHECK (kind IN ('forward', 'undo')),
  action_type text NOT NULL,

  -- The object actually mutated, already resolved through the pod-template
  -- owner chain. Stored so a reconciler can re-read it without a live cluster
  -- call to work out what to look at — the resolution needs an agent, and the
  -- agent may be exactly what went away.
  target_gvk       text NOT NULL,
  target_namespace text NOT NULL DEFAULT '',
  target_name      text NOT NULL,

  -- The single scalar this change sets, when it has one. Both the input to a
  -- reconciler's "did it actually land?" comparison and the value the settled
  -- remediation_executions row must carry so a later undo can still refuse
  -- when the field has moved.
  forward_applied_value         text,
  resource_version_precondition text,

  -- The compensating action captured before the mutation. Its whole value is
  -- that it survives the hub dying mid-execution, so it is written here, in
  -- the transaction that precedes the mutation, and copied onto the execution
  -- row when the attempt settles.
  rollback_action_type text,
  rollback_params      jsonb,
  rollback_description text,
  CONSTRAINT remediation_execution_attempts_rollback_complete
    CHECK ((rollback_action_type IS NULL) = (rollback_params IS NULL)),

  -- For kind = 'undo': the execution being undone, so a settlement can link
  -- the two the way the rollback endpoint does on the happy path.
  undo_of_execution_id text,

  -- Attribution, so an attempt settled minutes later by a background
  -- reconciler is still attributed to whoever authorised it rather than to a
  -- vague system actor. Mirrors executionActor's fields exactly, including
  -- the unattended flag migrations 000046/000047 keep distinguishable from
  -- "no actor".
  actor_id          text,
  actor_auth_method text NOT NULL,
  actor_source_ip   text,
  actor_reason      text,
  unattended        boolean NOT NULL DEFAULT false,

  -- Where the incident goes if this attempt turns out to have succeeded.
  -- NULL means "leave the incident's state alone", which is the honest answer
  -- for most rollback starting states: an undo is a statement about the
  -- cluster, not about where the incident is in its investigation lifecycle.
  success_state text,

  started_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,

  -- NULL until an outcome is recorded. execution_id names the
  -- remediation_executions row written in the same transaction that set this.
  settled_at   timestamptz,
  execution_id text
);

-- The reconciler's only query: unsettled attempts whose owner's deadline has
-- passed. Partial, because settled rows are history and are never swept.
CREATE INDEX remediation_execution_attempts_open_idx
  ON remediation_execution_attempts (expires_at ASC)
  WHERE settled_at IS NULL;

-- "Is there an unfinished attempt against this incident?" — asked before
-- dispatching a rollback, and by the reconciler's orphan pass.
CREATE INDEX remediation_execution_attempts_incident_idx
  ON remediation_execution_attempts (incident_id, started_at DESC);

-- Tenant-scoped, matching remediation_executions' own policy exactly
-- (migration 000031): this table is written and read from the same contexts,
-- which call data.SetRequestScope with no cluster list.
ALTER TABLE remediation_execution_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_execution_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_execution_attempts_tenant_scope ON remediation_execution_attempts
  USING (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_execution_attempts TO argus_app;
