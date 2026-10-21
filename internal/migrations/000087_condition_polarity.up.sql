-- BACKLOG.md E11 piece 3: AI-interpreted condition polarity. Kubernetes
-- condition polarity is inconsistent (Ready=True is healthy,
-- MemoryPressure=True is a problem), and this item's own text names a
-- hardcoded polarity table as its anti-pattern. This table instead PERSISTS
-- what was actually learned -- either inferred statistically from live
-- cluster samples (internal/agent's checkGenericConditions reports its own
-- majority-vote inference, and internal/conditionpolarity.Resolve trusts and
-- stores it when the sample clears the confidence bar) or, when there is not
-- enough live evidence to infer anything, asked of the model once
-- (internal/conditionpolarity.Resolve's Mechanism-2 fallback) -- one row per
-- (kind, condition type) pair, ever, for the life of the fact.
--
-- Deliberately NO row-level security, matching migration
-- 000016_signing_keys.up.sql's and 000018_org_settings.up.sql's decision and
-- reasoning, not just their shape: this is a fact about Kubernetes/CRD
-- *semantics* -- "does Ready=True mean healthy for a cert-manager
-- Certificate" is the same answer for every tenant and every cluster, not
-- tenant data. Its one real caller, internal/gateway's finding-ingestion
-- polarity gate (handleFinding, ahead of the request-scoped correlation
-- transaction that follows), runs the same way org_settings' own two
-- flagged call sites do -- with no per-request tenant/RLS context resolved
-- yet -- so a tenant_id-keyed policy here would gain nothing (the answer
-- never varies by tenant) while risking the exact startup/call-time-
-- ordering bug class this codebase has already hit three times.
--
-- kind is the bare Kind name (e.g. "Node", "Certificate"), not a full GVK:
-- a condition TYPE is a convention of the Kind's own API, and
-- BACKLOG.md E11 predicate 4's reference-integrity convention also only
-- ever names a bare Kind -- every caller in this mechanism already works in
-- bare-Kind terms (internal/agent/generic_predicates.go's kindIsNamespaced).
-- This does mean two different API groups that happen to share a Kind name
-- would share one cache row -- an accepted, documented limitation (see that
-- file's own doc comment), not an oversight.
CREATE TABLE condition_polarity (
  kind            text NOT NULL,
  condition_type  text NOT NULL,
  bad_value       text NOT NULL CHECK (bad_value IN ('True', 'False')),
  source          text NOT NULL CHECK (source IN ('statistical', 'model')),
  sample_count    integer NOT NULL DEFAULT 0,
  confidence      double precision,
  model_name      text,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, condition_type)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON condition_polarity TO argus_app;
