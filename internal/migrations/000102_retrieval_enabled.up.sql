-- PROJECT.md: retrieval (internal/knowledge.Store.RetrieveSimilar, wired
-- into both investigation backends' prompts as labelled prior-belief
-- context) measured 31% higher cost with no measurable confidence benefit
-- on one real repeated fault. One fault is not a verdict, but shipping an
-- unconditional cost increase on an inconclusive result is not acceptable
-- either — this is the real off switch that was missing: unconfiguring
-- embedding entirely would also disable the storage retrieval depends on,
-- which is not a control, only an accident.
--
-- NOT NULL DEFAULT false: every installation that has not deliberately
-- turned this on keeps today's behaviour — no retrieval call, no added
-- prompt tokens, no cost change — matching
-- autonomy_unattended_execution_enabled's own conservative-default
-- precedent (migration 000046) for the identical reason: a feature with an
-- open cost/benefit question must not be on by default.
ALTER TABLE org_settings
  ADD COLUMN retrieval_enabled boolean NOT NULL DEFAULT false;
