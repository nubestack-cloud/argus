-- Persist raw model answers (BACKLOG C2), and the parse error that made them
-- worth keeping.
--
-- The need is written down verbatim in internal/llm/cli_investigator.go, in a
-- comment that ends "Learned the hard way — a real investigation failed this way
-- and its answer was simply gone":
--
--   "The answer text itself is logged, truncated, because it is otherwise
--    unrecoverable: nothing persists it (analyses has no raw-answer column), so
--    without this line a failed parse leaves no way to see what the model actually
--    said and therefore no way to tell a prompt problem from a harness problem."
--
-- A log line is not enough for that job. It is gone on the next container restart,
-- it is not attached to the analysis it belongs to, and nobody reading an incident
-- can see it. These two columns are.
--
-- WHY ONLY ON FAILURE, and not a raw copy of every answer: when the parse
-- SUCCEEDS, root_cause / confidence / causal_chain / ruled_out already ARE the
-- answer, in structured form, and a raw duplicate would grow this table for no
-- information. When it FAILS, those columns hold nothing the model committed to,
-- and the raw text is the only record of what actually came back. So this is
-- targeted evidence about failures rather than a transcript log — which also keeps
-- the honest answer to "is this expensive?" a no.
--
-- Prerequisite for calibration (L3) and for the shadow-soak revisit (H3): both ask
-- "was the model right", and neither can be answered about a run whose output was
-- never recorded.
ALTER TABLE analyses
  ADD COLUMN raw_final_answer text,
  ADD COLUMN parse_error       text;

-- Nullable together, and the constraint says so: a parse_error with no answer
-- attached would be a diagnosis with the evidence thrown away, which is exactly
-- the situation this migration exists to end.
ALTER TABLE analyses
  ADD CONSTRAINT analyses_raw_answer_with_error
    CHECK ((parse_error IS NULL) = (raw_final_answer IS NULL));

-- Partial: the overwhelming majority of rows will have NULL here, and the only
-- query anyone wants is "show me the investigations whose output could not be
-- read", newest first.
CREATE INDEX analyses_parse_failures
  ON analyses (created_at DESC)
  WHERE parse_error IS NOT NULL;
