DROP INDEX IF EXISTS analyses_parse_failures;
ALTER TABLE analyses DROP CONSTRAINT IF EXISTS analyses_raw_answer_with_error;
ALTER TABLE analyses
  DROP COLUMN IF EXISTS parse_error,
  DROP COLUMN IF EXISTS raw_final_answer;
