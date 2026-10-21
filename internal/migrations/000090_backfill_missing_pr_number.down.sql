-- Reverses 000090 for symmetry: the repaired row, if present, loses its
-- backfilled pull request number again.
UPDATE incidents
   SET pr_number = NULL
 WHERE id = 'inc_01m0ntq9h0dxxcqn71qc3mewsb'
   AND pr_number = 5;
