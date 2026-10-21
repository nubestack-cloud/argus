ALTER TABLE org_settings
  DROP COLUMN IF EXISTS autonomy_auto_approve_max_risk,
  DROP COLUMN IF EXISTS autonomy_min_confidence_for_auto_approve,
  DROP COLUMN IF EXISTS autonomy_require_reversible_for_auto_approve;
