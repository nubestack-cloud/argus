-- BACKLOG.md R3: BatchExecution, the staged-rollout half of blast-radius
-- protection that migration 000046's cap deliberately left unbuilt (its own
-- doc comment: "the cap refuses; it does not stage").
--
-- WHAT THIS ADDS, AND WHAT IT DOES NOT REPLACE
--
-- blastradius.go's per-cluster/fleet-wide caps stay exactly as they are — the
-- hard ceiling on unattended execution volume, regardless of correlation.
-- This is an ADDITIONAL, more deliberate gate for the specific case fleet
-- correlation (internal/fleetgroup) already detects: several incidents
-- sharing a fleet_group_id, all eligible for the SAME unattended remediation
-- action_type, discovered around the same time. Instead of letting every one
-- of them execute as fast as the cap allows (or get silently retried by the
-- poller's next tick once the cap's rolling window has room again — see
-- internal/api/unattended.go's own investigation of that pre-existing
-- behaviour), a small first wave executes and the rest are held until wave
-- 1's own ValidationSweeper outcome is known.
--
-- one batch per (tenant, fleet_group_id, action_type), ever
--
-- Once a batch exists for a key, every incident that ever matches that key —
-- whether present at the moment the batch was created or arriving later as a
-- straggler — becomes a member of THAT SAME batch (as a wave-2 member,
-- since wave 1 already ran) rather than starting a new one. Simpler than
-- reasoning about "epochs" of the same recurring fault, and it is the safe
-- direction: a batch that concluded 'blocked' keeps holding later arrivals
-- of the identical fault+fix rather than re-litigating each time, and a
-- batch that concluded 'released' has already proven the fix, so a later
-- arrival is simply not held. See internal/orchestrator/batch.go for the
-- full decision logic.
CREATE TABLE unattended_batches (
  id              text        PRIMARY KEY, -- 'ubatch_...' (domain.PrefixUnattendedBatch)
  tenant_id       text        NOT NULL REFERENCES organisations(id),

  -- Not a foreign key: fleet_group_id is a display-only, sometimes-NULL,
  -- sometimes-reassigned grouping id (internal/fleetgroup.Recompute is the
  -- only writer, and it moves incidents between group ids as membership
  -- changes) rather than a row identity anything else references — the same
  -- reason incidents.fleet_group_id itself is a bare text column.
  fleet_group_id  text        NOT NULL,
  action_type     text        NOT NULL,

  -- wave1_pending: wave 1 has been assigned and is flowing through the
  --   ordinary candidate/budget/breaker pipeline like any other unattended
  --   candidate; wave 2 is held.
  -- released: wave 1 validated successfully (every wave-1 incident reached
  --   Resolved); wave 2 is no longer held and flows through the ordinary
  --   pipeline like any other unattended candidate.
  -- blocked: at least one wave-1 incident's validation did NOT hold
  --   (Reopened, or any other outcome besides Resolved reached from
  --   Executing/Validating); wave 2 stays held indefinitely. A human can
  --   still approve any individual held incident by hand — this only gates
  --   the UNATTENDED path, exactly like every other guardrail in
  --   unattended.go.
  -- abandoned: wave 1 never reached a conclusion within
  --   maxBatchHoldDuration (batch.go) — e.g. every wave-1 candidate kept
  --   losing to the blast-radius cap and never actually executed. Wave 2
  --   stays held; this status exists for visibility ("why is this still
  --   sitting here") rather than to trigger a release, since by the time
  --   this fires wave 2's own recommendations have almost always also aged
  --   out of maxUnattendedPlanAge and stopped being unattended candidates
  --   at all, independently of this table.
  status          text        NOT NULL DEFAULT 'wave1_pending'
                    CHECK (status IN ('wave1_pending', 'released', 'blocked', 'abandoned')),

  -- How many of this batch's members were assigned to wave 1 at creation
  -- time. See batch.go's waveOneSize for the sizing rationale (small and
  -- deliberately conservative, not a fixed fraction).
  wave1_size      integer     NOT NULL CHECK (wave1_size > 0),
  -- The batch's size as of its most recent membership write. NOT a live
  -- COUNT(*) — updated incrementally as members are added — but always
  -- matches (SELECT count(*) FROM unattended_batch_members WHERE batch_id =
  -- this row's id) by construction, since batch.go is the only writer of
  -- both.
  total_size      integer     NOT NULL CHECK (total_size >= wave1_size),

  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  -- Set the moment status leaves 'wave1_pending'. NULL while pending.
  resolved_at     timestamptz,
  CONSTRAINT unattended_batches_resolved_at_matches_status
    CHECK ((status = 'wave1_pending') = (resolved_at IS NULL))
);

-- Enforces "one batch per key, ever" — see this file's header.
CREATE UNIQUE INDEX unattended_batches_key
  ON unattended_batches (tenant_id, fleet_group_id, action_type);

-- What the per-sweep outcome check (batch.go's resolveBatchOutcomes) scans:
-- every batch still waiting on wave 1.
CREATE INDEX unattended_batches_pending_idx
  ON unattended_batches (tenant_id, status) WHERE status = 'wave1_pending';

ALTER TABLE unattended_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE unattended_batches FORCE ROW LEVEL SECURITY;
-- Tenant-scoped, matching remediation_recommendations/remediation_executions/
-- circuit_breaker_trips' own precedent (all three comments give the same
-- reason): the unattended sweeper runs fleet-wide with
-- app.accessible_cluster_ids left empty, and a cluster_id-keyed policy would
-- read this table as permanently empty from that context.
CREATE POLICY unattended_batches_scope ON unattended_batches
  USING (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON unattended_batches TO argus_app;

-- One row per incident a batch has ever claimed. cluster_id and tenant_id are
-- denormalized (lld/05-data-model.md §6) even though both are reachable via
-- incidents/unattended_batches, because this table is read fleet-wide by the
-- sweeper on every tick and a join back through incidents for a column this
-- cheap to duplicate is pure overhead.
CREATE TABLE unattended_batch_members (
  id           text        PRIMARY KEY, -- 'ubm_...' (domain.PrefixUnattendedBatchMember)
  batch_id     text        NOT NULL REFERENCES unattended_batches(id),
  tenant_id    text        NOT NULL REFERENCES organisations(id),
  cluster_id   text        NOT NULL REFERENCES clusters(id),
  -- NOT a foreign key: incidents' primary key is the composite (id,
  -- first_seen) its own partitioning needs (migration 000005), so nothing
  -- else in this codebase declares REFERENCES incidents(id) either — see
  -- remediation_recommendations/remediation_executions' identical
  -- incident_id column for the precedent.
  incident_id  text        NOT NULL,

  -- 1: a wave-1 member — always eligible for the ordinary unattended
  --    pipeline (subject to every existing gate), regardless of the batch's
  --    status, because wave 1 executing is what produces the validation
  --    signal the rest of the batch is waiting on.
  -- 2: everyone else, including stragglers who joined after the batch
  --    already existed. Eligible for the ordinary pipeline only once the
  --    batch's status is 'released'.
  wave_number  integer     NOT NULL CHECK (wave_number IN (1, 2)),
  created_at   timestamptz NOT NULL DEFAULT now(),

  -- One membership per (batch, incident): a straggler discovered on a later
  -- sweep tick is an INSERT ... ON CONFLICT DO NOTHING against this, not a
  -- new row every tick it keeps being seen. An incident CAN belong to
  -- different batches for different action_type keys (a re-analysis that
  -- proposes a different fix for the same fleet group is a different
  -- coordination scope, per this file's header), so the constraint is
  -- per-batch, not a bare UNIQUE(incident_id).
  UNIQUE (batch_id, incident_id)
);

CREATE INDEX unattended_batch_members_batch_idx
  ON unattended_batch_members (batch_id, wave_number);
-- What batch.go's per-sweep candidate lookup keys on: "does this incident
-- already belong to a batch, and if so which one/which wave".
CREATE INDEX unattended_batch_members_incident_idx
  ON unattended_batch_members (incident_id);

ALTER TABLE unattended_batch_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE unattended_batch_members FORCE ROW LEVEL SECURITY;
CREATE POLICY unattended_batch_members_scope ON unattended_batch_members
  USING (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON unattended_batch_members TO argus_app;
