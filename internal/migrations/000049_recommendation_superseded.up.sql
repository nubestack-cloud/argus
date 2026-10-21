-- A plan that has been superseded by a source fix must stop being approvable.
--
-- THE FAILURE THIS PREVENTS, OBSERVED LIVE (WORKLOG §142)
--
-- The first real end-to-end GitOps run went: bad image tag committed to Git ->
-- Argo synced it -> ImagePullBackOff -> incident -> ARGUS proposed an in-place
-- RevertContainerImage plan AND opened a pull request fixing the tag at source
-- -> the pull request was merged -> Argo synced the fix -> the workload
-- recovered.
--
-- The incident then sat in AwaitingApproval with that in-place plan still
-- approvable, and a preflight showed what approving it would now do:
--
--     spec.template.spec.containers[web].image:
--       'nginx:1.27-alpine' -> 'nginx:1.27-alpine-typo'
--
-- It would have RE-BROKEN the workload. RevertContainerImage resolves "the
-- previous revision's image" from the cluster's own ReplicaSet history at
-- APPROVAL time, so once the fix landed, the previous revision was the broken
-- one and the plan's meaning silently inverted. Nothing marked it stale. The
-- only things between an operator and that outcome were the GitOps guardrail
-- (which they can deliberately confirm past, and would, having just been told
-- the object is Argo-managed) and running a preflight and reading it.
--
-- WHY THIS COLUMN RATHER THAN A NEW INCIDENT STATE
--
-- lld/08's state machine has no state meaning "a pull request is open", and
-- inventing one would change the meaning of AwaitingApproval for every existing
-- reader — including the unattended sweeper's candidate query. This is a fact
-- about the RECOMMENDATION ("something better than this exists now"), not about
-- the incident's position in its lifecycle, so it belongs on the recommendation.
--
-- Deliberately NOT a general "stale plan" mechanism. It records one specific,
-- known fact: ARGUS itself proposed a durable fix at the source for this
-- incident. Detecting staleness in general — that the world moved under a plan —
-- is a real and much larger problem, and pretending this solves it would be
-- worse than leaving it visibly unsolved.
ALTER TABLE remediation_recommendations
  ADD COLUMN superseded_at timestamptz,
  -- The pull request that superseded it. Stored as the URL rather than an id
  -- because it is what a human needs: the answer to "so what should I look at
  -- instead" has to be clickable, and it is the only durable handle on the PR
  -- that exists (the pull_requests table from migration 000006 references
  -- remediation_plans, which nothing writes).
  ADD COLUMN superseded_by_url text,
  ADD CONSTRAINT remediation_recommendations_superseded_together
    CHECK ((superseded_at IS NULL) = (superseded_by_url IS NULL));

-- The approve path checks this per recommendation, by id, so no index is needed
-- beyond the primary key. Stated so nobody adds one on the theory that a new
-- nullable column needs one.
