-- lld/14-adrs.md ADR-17: a second kind of AI provider backend, in which an
-- external coding-agent CLI (claude/codex) owns the investigation loop and
-- ARGUS supplies read-only tools to it over MCP, instead of ARGUS driving the
-- loop itself. Opt-in and off by default.
--
-- llm_provider_kind is deliberately NULLable with no DEFAULT rather than
-- DEFAULT 'api'. Both would behave identically for a fresh install, but NULL
-- carries a distinction that matters: it means "nobody has ever expressed a
-- preference," which is exactly the state every pre-existing deployment is in
-- on upgrade. internal/settings.NormalizeProviderKind maps NULL/'' to 'api',
-- so an upgraded install keeps precisely the behaviour it already had, and no
-- backfill UPDATE is needed. The CHECK still constrains real values, so a
-- typo'd kind can never be stored — internal/settings.Update and
-- internal/api's request validation guard the same thing at two higher
-- layers, on the reasoning that an unrecognized kind here would break
-- analysis org-wide until corrected.
ALTER TABLE org_settings
  ADD COLUMN llm_provider_kind text
    CHECK (llm_provider_kind IS NULL OR llm_provider_kind IN ('api', 'cli'));

-- Runner connection (B12's hub->runner direction, lld/01-threat-model.md §4).
-- cli_runner_token is a bearer credential and is handled exactly like
-- llm_api_key already is: never returned by GET /api/v1/admin/settings, which
-- reports only a cli_runner_token_set boolean.
ALTER TABLE org_settings ADD COLUMN cli_runner_url text;
ALTER TABLE org_settings ADD COLUMN cli_runner_token text;
ALTER TABLE org_settings
  ADD COLUMN cli_agent text
    CHECK (cli_agent IS NULL OR cli_agent IN ('claude', 'codex'));

-- lld/07-analysis-contracts.md §10.5: cost_basis records whether this
-- analysis's cost_usd is a real measured number or structurally unavailable,
-- so nothing downstream has to infer it from a zero.
--
-- This is the schema half of that section's core argument: under a
-- subscription-authenticated CLI backend, per-investigation cost genuinely
-- cannot be observed, and persisting cost_usd = 0 would make a fabricated
-- number indistinguishable from a real free call. Insights and the spend
-- ceiling read this column to decide between "$0.00" and "unavailable" —
-- the same discipline that already gives a partial analysis
-- confidence = NULL rather than inventing a number.
--
-- NULL means "written before this column existed," which for every existing
-- row is truthfully 'metered' (the api backend was the only one that existed)
-- — but it is backfilled explicitly below rather than inferred at read time,
-- so the column means exactly one thing everywhere.
ALTER TABLE analyses
  ADD COLUMN cost_basis text
    CHECK (cost_basis IS NULL OR cost_basis IN ('metered', 'subscription', 'unknown'));

UPDATE analyses SET cost_basis = 'metered' WHERE cost_basis IS NULL;
