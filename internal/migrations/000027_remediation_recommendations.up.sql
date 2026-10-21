-- Phase 2, slice 2: plan authoring + the incident orchestrator's real state
-- transitions + an approval queue — see STATUS.md's own numbered entry for
-- this round for the full picture. Still explicitly short of any real
-- execution (no signing, no executor, no PR-opening) — see
-- internal/orchestrator's package doc comment.
--
-- NAMING NOTE, read before assuming this collides with
-- lld/05-data-model.md §3.6's remediation_plans/plan_actions/approvals
-- tables (already created by migration 000006_remediation.up.sql, already
-- RLS-wired by 000009_row_level_security.up.sql's generic cluster_id-scoped
-- loop): those tables are the FULL, execution-ready contract
-- lld/08-remediation-contracts.md §5-§7 specifies — an HMAC plan signature
-- (§7), an expires_at an overlap-window key rotation depends on, a channel
-- (pullRequest/inPlace/guidance) a real executor dispatches on, and a
-- plan_hash used for redelivery idempotency (§6). None of that machinery
-- exists anywhere in this codebase yet: no signing key, no executor, no
-- channel-specific dispatch. Reusing that table under this task's simpler,
-- unsigned, execution-free shape would mean fabricating a signature/
-- expires_at/channel with no real meaning behind them just to satisfy their
-- NOT NULL constraints — exactly the kind of "pretend this is more complete
-- than it is" this codebase's own conventions reject elsewhere (see
-- cost_usd's honest-zero precedent, internal/api/analyze.go's
-- persistAnalysis doc comment).
--
-- So: two new, distinctly-named tables for the honest, execution-free slice
-- this task actually builds. remediation_plans/plan_actions/approvals
-- (migration 000006) remain completely untouched and reserved for the real
-- signed/executable pipeline a future task builds; that future task's own
-- job is to decide how (or whether) an approved remediation_recommendation
-- here gets promoted into a real, signed remediation_plans row there.

CREATE TABLE remediation_recommendations (
  id                text PRIMARY KEY,             -- 'plan_...' (domain.PrefixPlan) — same conceptual ID space as the future real remediation_plans table; the two never collide, since ULIDs are globally unique regardless of which table ends up holding one.
  incident_id       text NOT NULL,
  tenant_id         text NOT NULL,
  cluster_id        text NOT NULL,
  analysis_id       text NOT NULL,                -- lineage: the specific Analysis (an_...) whose root cause this recommends fixing.
  action_type       text NOT NULL CHECK (action_type IN ('ScaleDeployment', 'RestartPod', 'OpenPR')), -- internal/remediation.ActionType's closed set, mirrored here so a row can never name a 4th type even via a direct SQL edit.
  target_gvk        text NOT NULL,
  target_namespace  text,                         -- nullable: some future action types (none today) might target a cluster-scoped object with no namespace.
  target_name       text NOT NULL,
  params            jsonb NOT NULL,
  reversible        boolean NOT NULL,
  risk_level        text NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
  -- gate_outcome/gate_reason: internal/remediation.Evaluate's actual
  -- decision for THIS plan against the autonomy policy in force at the
  -- moment it was proposed — recorded once, at proposal time, never
  -- recomputed later even if the policy changes afterward. This is what
  -- lets GET /api/v1/approvals show "why is this awaiting approval" without
  -- re-running the gate against whatever policy happens to be configured
  -- when someone opens the page.
  gate_outcome      text NOT NULL CHECK (gate_outcome IN ('AutoApprove', 'NeedsApproval', 'Blocked')),
  gate_reason       text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX remediation_recommendations_incident_idx ON remediation_recommendations (incident_id, created_at DESC);

ALTER TABLE remediation_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_recommendations FORCE ROW LEVEL SECURITY;
-- Tenant_id-keyed from the start (not the generic cluster_id-scoped loop's
-- shape), matching migrations 000013/000015's already-learned fix: a
-- policy keyed on app.accessible_cluster_ids alone would permanently block
-- every read/write from a general-purpose request, since nothing populates
-- that session variable outside a genuinely cluster-scoped route.
CREATE POLICY remediation_recommendations_tenant_scope ON remediation_recommendations
  USING (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_recommendations TO argus_app;

CREATE TABLE remediation_approval_decisions (
  id                 text PRIMARY KEY,            -- 'appr_...' (domain.PrefixApproval)
  recommendation_id  text NOT NULL REFERENCES remediation_recommendations(id),
  incident_id        text NOT NULL,
  tenant_id          text NOT NULL,
  cluster_id         text NOT NULL,
  actor_id           text NOT NULL,
  verdict            text NOT NULL CHECK (verdict IN ('approved', 'rejected')),
  reason             text,                        -- required by the API layer for a rejection, optional for an approval; not a DB-level CHECK, since that distinction is a request-validation concern, not a data-integrity one.
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX remediation_approval_decisions_recommendation_idx ON remediation_approval_decisions (recommendation_id, created_at DESC);

ALTER TABLE remediation_approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_approval_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_approval_decisions_tenant_scope ON remediation_approval_decisions
  USING (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_approval_decisions TO argus_app;
