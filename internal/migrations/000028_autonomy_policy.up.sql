-- Closes the gap WORKLOG.md §50 flagged explicitly: internal/orchestrator's
-- Advance/ApplyAnalysisResult evaluate every proposed remediation plan
-- against internal/remediation.Evaluate using orchestrator
-- .DefaultAutonomyPolicy, a hardcoded, non-live-editable
-- remediation.AutonomyPolicy{AutoApproveMaxRisk: low, MinConfidenceForAuto
-- Approve: 0.90, RequireReversibleForAutoApprove: true}. This migration adds
-- the DB-backed override for exactly those three fields, following the same
-- convention every other org_settings column already uses (migration
-- 000018's header comment) and, specifically, the no-env-var-tier precedent
-- migrations 000020/000024/000026 established for a brand-new setting with
-- no prior ARGUS_* environment variable whose behavior needs preserving.
--
-- IMPORTANT, read before assuming this weakens anything: none of these three
-- columns can affect internal/remediation.Evaluate's hard, non-configurable
-- safety floor ("high risk + irreversible always needs a human," STATUS.md
-- §31) -- that check runs unconditionally, before AutonomyPolicy is ever
-- consulted, and has no field anywhere that could disable it. What these
-- three columns configure is exactly, and only, the same
-- remediation.AutonomyPolicy struct DefaultAutonomyPolicy already
-- hardcodes -- the graduated-autonomy ceiling DESIGN.md
-- §9.4 describes as something "surfaced in the UI," not the floor beneath
-- it.
--
-- autonomy_auto_approve_max_risk: nullable text, one of 'low'/'medium'/
-- 'high' (internal/remediation.RiskLevel's closed enum -- 'forbidden' has no
-- representative action type in this codebase's closed ActionType set yet,
-- per plan.go's own comment, so it stays unmodeled here too). NULL means
-- "not configured in the DB" -- internal/settings.Resolve leaves this tier
-- unresolved (no env var to fall back to) and internal/orchestrator applies
-- DefaultAutonomyPolicy.AutoApproveMaxRisk (low) as the further, hardcoded
-- fallback tier, mirroring analysis_max_iterations/analysis_time_limit_
-- seconds' precedent exactly (migration 000019) rather than auto_analysis_
-- severities'/disabled_detector_ids' "NULL is itself the safe steady state"
-- precedent: an installation that has never touched this setting resolves
-- to the exact same effective policy it already had before this migration
-- ran, not a new, different default.
--
-- autonomy_min_confidence_for_auto_approve: nullable numeric(4,3) (same
-- precision as migration 000006's confidence column), CHECK-constrained to
-- [0,1]. NULL falls back to DefaultAutonomyPolicy.MinConfidenceForAutoApprove
-- (0.90) for the identical reason.
--
-- autonomy_require_reversible_for_auto_approve: boolean NOT NULL DEFAULT
-- true -- the one field of the three with no "unconfigured, consult a
-- further tier" state, matching auto_analysis_enabled's precedent (migration
-- 000020): true and "never touched" are the same effective value, and it
-- defaults to the SAFER of the two possible booleans (matching
-- DefaultAutonomyPolicy's own true), not false, so a fresh install is never
-- less conservative than DefaultAutonomyPolicy was.
ALTER TABLE org_settings
  ADD COLUMN autonomy_auto_approve_max_risk text
    CHECK (autonomy_auto_approve_max_risk IS NULL
           OR autonomy_auto_approve_max_risk IN ('low', 'medium', 'high')),
  ADD COLUMN autonomy_min_confidence_for_auto_approve numeric(4,3)
    CHECK (autonomy_min_confidence_for_auto_approve IS NULL
           OR (autonomy_min_confidence_for_auto_approve >= 0 AND autonomy_min_confidence_for_auto_approve <= 1)),
  ADD COLUMN autonomy_require_reversible_for_auto_approve boolean NOT NULL DEFAULT true;
