ALTER TABLE remediation_policies DROP CONSTRAINT IF EXISTS fk_current_version;
DROP TABLE IF EXISTS policy_versions;
DROP TABLE IF EXISTS remediation_policies;
