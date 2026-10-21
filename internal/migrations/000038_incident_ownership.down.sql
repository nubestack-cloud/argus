-- Reverses 000038. Losing the column means the "your fix will be reverted"
-- caveat falls back to scraping an analysis's causal chain, which is null on the
-- cli backend — the caveat silently stops appearing rather than erroring, so a
-- rollback here quietly reduces safety information. No data other than the
-- cached ownership is affected.
ALTER TABLE incidents DROP COLUMN IF EXISTS ownership;
