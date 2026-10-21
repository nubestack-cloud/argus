-- Fleet enrollment tokens: one long-lived, multi-use, revocable token a fleet
-- can share, so the agent chart can be rolled out to many clusters by GitOps
-- (an Argo CD ApplicationSet, Flux, Rancher Fleet) with the token in a Secret.
--
-- ttl_class 'F' is the fleet class. name labels it for the people managing
-- it. auto_accept accepts every cluster that enrolls with it, on behalf of
-- the issuer, who must hold cluster:accept when issuing; revoked_at ends it
-- before its expiry.
ALTER TABLE enrollment_tokens DROP CONSTRAINT enrollment_tokens_ttl_class_check;
ALTER TABLE enrollment_tokens ADD CONSTRAINT enrollment_tokens_ttl_class_check CHECK (ttl_class IN ('A', 'B', 'C', 'F'));
ALTER TABLE enrollment_tokens
  ADD COLUMN name        text NOT NULL DEFAULT '',
  ADD COLUMN auto_accept boolean NOT NULL DEFAULT false,
  ADD COLUMN revoked_at  timestamptz;
