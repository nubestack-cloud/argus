-- BACKLOG.md G7 "Residual race in refresh-token reuse detection": closing the
-- race by locking a refresh token's rotation chain ("family") up front,
-- rather than a bounded re-walk or SERIALIZABLE. Locking requires something
-- stable to lock ON — refresh_tokens had no such identifier; a chain was only
-- discoverable by walking replaced_by. This adds family_id: every token
-- descended from one original IssueRefreshToken call (including that first
-- token itself) shares the same family_id, so internal/authz.RotateRefreshToken
-- can take `SELECT ... WHERE family_id = $1 FOR UPDATE` at the START of
-- rotation, before reading anything about the presented token's own validity,
-- and serialize every concurrent rotation/reuse-detection attempt anywhere in
-- that chain against every other one — not just two attempts on the exact
-- same row, which the existing per-row FOR UPDATE already handled.
--
-- family_id is not a fresh domain.NewID: refresh_tokens' primary key is
-- already a sha256 hex hash rather than a prefixed ULID (it is a hash of the
-- opaque token, not an assigned identifier), so this reuses that same shape —
-- family_id is simply the token_hash of the chain's ROOT token (the one
-- IssueRefreshToken created, with no predecessor). That value is irreversible
-- and was already stored as a refresh_tokens.token_hash, so exposing it again
-- as another column's value discloses nothing new.
ALTER TABLE refresh_tokens ADD COLUMN family_id text;

-- Backfill every existing row: walk forward from each chain's root (a row no
-- other row's replaced_by points at) via replaced_by, propagating the root's
-- own token_hash as family_id to every descendant, including the root itself.
WITH RECURSIVE root_of(token_hash, root) AS (
  SELECT r.token_hash, r.token_hash
  FROM refresh_tokens r
  WHERE NOT EXISTS (
    SELECT 1 FROM refresh_tokens p WHERE p.replaced_by = r.token_hash
  )
  UNION ALL
  SELECT nxt.token_hash, ro.root
  FROM root_of ro
  JOIN refresh_tokens cur ON cur.token_hash = ro.token_hash
  JOIN refresh_tokens nxt ON nxt.token_hash = cur.replaced_by
)
UPDATE refresh_tokens t
SET family_id = ro.root
FROM root_of ro
WHERE t.token_hash = ro.token_hash;

-- Every row has a root, so every row now has a family_id (a chain of length 1
-- gets family_id = its own token_hash from the base case above) — safe to
-- require it going forward, the same way the two hand-issuance sites
-- (IssueRefreshToken, RotateRefreshToken) always set it.
ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;

-- The family lock's WHERE clause and the reuse-detection chain-revoke UPDATE
-- both filter on family_id, and a family accumulates one row per rotation
-- (daily, for up to RefreshTokenTTL) — worth an index rather than a seq scan
-- on a table that also serves every login/refresh request.
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
