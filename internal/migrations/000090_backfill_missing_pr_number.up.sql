-- A one-time repair of a single incident row in a pre-release development
-- database: a pull request opened before migration 000058 added
-- incidents.pr_number, which left the merge sweeper unable to ever see it.
-- It matches nothing in any other database; the version is kept so the
-- migration sequence stays unbroken.
UPDATE incidents
   SET pr_number = 5
 WHERE id = 'inc_01m0ntq9h0dxxcqn71qc3mewsb'
   AND pr_number IS NULL
   AND pr_url IS NOT NULL;
