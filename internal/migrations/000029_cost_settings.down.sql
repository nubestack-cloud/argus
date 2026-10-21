ALTER TABLE org_settings
  DROP COLUMN price_per_million_input_tokens,
  DROP COLUMN price_per_million_cached_tokens,
  DROP COLUMN price_per_million_output_tokens,
  DROP COLUMN daily_spend_ceiling_usd;
