-- Add 'forbidden' to remediation_recommendations.risk_level's CHECK
-- constraint (BACKLOG.md R4, DESIGN.md §9.3's fourth risk tier:
-- "never, at any confidence").
--
-- Same bug class migrations 000040 and 000056 already hit twice for
-- action_type: a Go-side enum value (RiskForbidden, internal/remediation/
-- plan.go) becomes persistable (RiskLevel.Valid() now accepts it) before the
-- database's own CHECK constraint is told about it, and the first plan to
-- carry the new value fails at INSERT time instead of being handled by the
-- gate. TestRiskLevelCheckConstraintAcceptsEveryRiskLevel
-- (internal/orchestrator) is risk_level's own version of
-- TestActionTypeCheckConstraintAcceptsEveryActionType, added alongside this
-- migration so this is the last time this particular lesson needs relearning
-- for THIS column.
--
-- forbidden reaches this column only via a model self-declaring
-- "riskLevel": "forbidden" against the prompt's own instructions (it is
-- never offered as an option in internal/llm/toolloop.go's SystemPrompt) —
-- Evaluate treats that as an absolute refusal (Blocked) rather than trusting
-- it, but the plan is still persisted for visibility, same as any other
-- Blocked plan. The other path to RiskForbidden — a target namespace
-- carrying argus.io/protected — is checked live at execution time
-- (internal/execution's preparePlan) and never becomes a
-- recommendation's declared risk_level at all, so this widening is pure
-- defense-in-depth, not something a normal analysis run is expected to hit.
ALTER TABLE remediation_recommendations DROP CONSTRAINT remediation_recommendations_risk_level_check;
ALTER TABLE remediation_recommendations ADD CONSTRAINT remediation_recommendations_risk_level_check
  CHECK (risk_level IN ('low', 'medium', 'high', 'forbidden'));
