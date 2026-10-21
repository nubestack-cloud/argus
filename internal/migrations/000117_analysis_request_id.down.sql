-- Drops the column. Nothing else references it: it is written by
-- PersistAnalysis and read only by a human correlating logs with rows, so
-- dropping it loses the correlation for existing rows and nothing more.
ALTER TABLE analyses DROP COLUMN request_id;
