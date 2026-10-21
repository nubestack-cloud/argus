DROP TABLE IF EXISTS analysis_embeddings;

-- Deliberately NOT `DROP EXTENSION vector` — an extension is a
-- cluster-wide-ish object other future migrations may come to depend on,
-- and dropping it here would be a much larger blast radius than reverting
-- this one table.
