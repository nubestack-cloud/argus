-- PROJECT.md CI-P9 (d): posture checks the organisation turns off, and
-- namespaces it leaves out of posture, set on the hub for every cluster.
-- Added to whatever each agent's chart already disables or ignores.
ALTER TABLE org_settings
  ADD COLUMN posture_disabled_checks text[] NOT NULL DEFAULT '{}',
  ADD COLUMN posture_ignored_namespaces text[] NOT NULL DEFAULT '{}';
