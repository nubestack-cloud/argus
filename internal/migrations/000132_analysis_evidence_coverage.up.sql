-- PROJECT.md IN6: what an investigation could and could not read — reads
-- answered, empty, denied, failed and truncated, and tools not offered —
-- counted from the real recorded tool calls. NULL for analyses written before
-- this column, and for a cli run whose tool ledger could not be read.
ALTER TABLE analyses ADD COLUMN evidence_coverage jsonb;
