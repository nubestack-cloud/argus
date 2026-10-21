-- Match a repository by its identity, not by the URL string someone typed.
--
-- THE BUG THIS FIXES
--
-- internal/scm.Store.ProviderFor looked a binding up with `WHERE b.url = $1`,
-- where $1 is the repository URL a GitOps controller reports (an Argo CD
-- Application's spec.source.repoURL, a Flux GitRepository's spec.url, a Fleet
-- GitRepo's spec.repo). That is an exact string comparison between two values
-- produced by different people for different purposes, and it failed four of the
-- five forms a real installation produces:
--
--   registered: https://github.com/org/platform-config.git
--   argo says:  https://github.com/org/platform-config          -> no match
--               https://github.com/org/platform-config.git/     -> no match
--               https://GitHub.com/org/platform-config.git      -> no match
--               git@github.com:org/platform-config.git          -> no match
--
-- Each failure surfaced as "no binding for this repository — register it with a
-- token that may write to it", i.e. it told the operator to do the thing they
-- had already done. The pull-request path was unreachable and the error pointed
-- away from the cause.
--
-- WHY A COLUMN RATHER THAN NORMALISING IN THE QUERY
--
-- Three reasons, and the third is the one that matters most:
--
--   1. It is indexable. A lookup that normalises in SQL cannot use an index.
--   2. The normalisation is defined once, in Go (scm.RepoKey), rather than once
--      per query in a dialect where getting it subtly different is easy.
--   3. It can be UNIQUE. Today the same repository can be registered twice under
--      two spellings, giving one repository two credentials — and then which one
--      gets used depends on which spelling the controller happens to report.
--      That is a correctness problem, not untidiness, and only a constraint can
--      actually prevent it.
ALTER TABLE repository_bindings ADD COLUMN repo_key text;

-- Backfill with the same normalisation scm.RepoKey applies: lowercase, strip a
-- `.git` suffix and surrounding slashes, drop any port, keep only host, owner and
-- name. Deliberately expressed in SQL rather than by a one-off Go pass so the
-- migration is self-contained and a restore replays identically.
--
-- Only https URLs exist in this column today (SaveBinding has always validated
-- through ParseRepoURL, which is https-only), so this does not need to handle the
-- scp-like `git@host:owner/name` form that ParseRepoRef accepts on the read side.
UPDATE repository_bindings
   SET repo_key = lower(
         regexp_replace(
           regexp_replace(url, '^https://', ''),   -- host/owner/name(.git)(/)
           '(\.git)?/*$', ''                       -- trailing .git and slashes
         )
       )
 WHERE repo_key IS NULL;

-- Any row that could not be normalised is a row whose URL was never a valid
-- repository URL, which SaveBinding's validation should have made impossible.
-- Failing here is correct: a NULL key would silently never match anything, which
-- is the exact failure mode this migration exists to remove.
ALTER TABLE repository_bindings ALTER COLUMN repo_key SET NOT NULL;

-- If this index fails to build, the installation has two bindings for one
-- repository under different spellings, each with its own credential. That is
-- genuinely ambiguous — nothing can decide which token was meant — so the
-- migration stops and an operator removes the duplicate rather than the schema
-- picking one arbitrarily.
CREATE UNIQUE INDEX repository_bindings_repo_key_idx
  ON repository_bindings (tenant_id, repo_key);
